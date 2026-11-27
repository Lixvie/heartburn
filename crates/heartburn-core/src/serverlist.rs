//! Mozilla Remote Settings VPN server list synchronization, `nsIVersionComparator`
//! + JEXL `filter_expression` evaluator, and candidate selection (`serverlist/`).

use std::cmp::Ordering;
use std::collections::HashMap;
use std::sync::Arc;

use bytes::Bytes;
use http::{HeaderMap, Method};
use serde::{Deserialize, Serialize};

use crate::controlplane::{ControlPlaneClient, RequestOptions, apply_fxa_headers};
use crate::error::ServerListError;
use crate::storage::Storage;

pub const REMOTE_SETTINGS_URL: &str =
    "https://firefox.settings.services.mozilla.com/v1/buckets/main/collections/vpn-serverlist/records";
pub const PRODUCT_DETAILS_URL: &str =
    "https://product-details.mozilla.org/1.0/firefox_versions.json";
pub const DEFAULT_FIREFOX_VERSION: &str = "160.0a1";
pub const RECOMMENDED_COUNTRY_CODE: &str = "REC";

/// Fallback standby exit countries tried in order on `ServerFailover`.
pub const FAILOVER_STANDBY_COUNTRIES: &[&str] = &["NL", "DE", "BE", "FR", "GB", "AT"];

const SERVERS_CACHE_FILE: &str = "servers.json";
const SELECTION_CACHE_FILE: &str = "selection.json";

/// Firefox JEXL evaluation environment matching Mozilla VPN Proxy Remote Settings.
#[derive(Debug, Clone)]
pub struct JexlEnv {
    pub version: String,
    pub os: String,
    pub channel: String,
    pub extra: HashMap<String, String>,
}

impl Default for JexlEnv {
    fn default() -> Self {
        let os = if cfg!(target_os = "macos") {
            "Darwin"
        } else if cfg!(target_os = "windows") {
            "WINNT"
        } else if cfg!(target_os = "android") {
            "Android"
        } else {
            "Linux"
        };
        Self {
            version: DEFAULT_FIREFOX_VERSION.to_owned(),
            os: os.to_owned(),
            channel: "nightly".to_owned(),
            extra: HashMap::new(),
        }
    }
}

/// Single proxy endpoint parsed from Remote Settings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProxyCandidate {
    pub country_code: String,
    pub country_name: String,
    pub city: String,
    pub host: String,
    pub port: u16,
    pub weight: u32,
}

impl ProxyCandidate {
    /// Returns `host:port`.
    pub fn addr(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }
}

/// Persisted last-selected server state (`selection.json`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SelectionCache {
    pub server: String,
    pub country_code: String,
    pub country_name: String,
    pub city: String,
    pub selected_at_unix: u64,
}

#[derive(Debug, Deserialize)]
struct RemoteSettingsEnvelope {
    data: Vec<RemoteServerRecord>,
}

#[derive(Debug, Deserialize)]
struct RemoteServerRecord {
    #[serde(default)]
    country: String,
    #[serde(default, alias = "country_name")]
    name: String,
    #[serde(default)]
    city: String,
    #[serde(default)]
    servers: Vec<RemoteEndpoint>,
    #[serde(default)]
    cities: Vec<RemoteCity>,
    #[serde(default)]
    filter_expression: String,
    #[serde(default)]
    visible: Option<bool>,
}

#[derive(Debug, Deserialize)]
struct RemoteCity {
    #[serde(default)]
    name: String,
    #[serde(default)]
    servers: Vec<RemoteEndpoint>,
}

#[derive(Debug, Deserialize)]
struct RemoteEndpoint {
    #[serde(default, alias = "hostname")]
    host: String,
    #[serde(default = "default_https_port")]
    port: u16,
    #[serde(default = "default_weight")]
    weight: u32,
}

fn default_https_port() -> u16 {
    443
}

fn default_weight() -> u32 {
    100
}

/// Mozilla Remote Settings server-list manager + JEXL evaluator.
#[derive(Clone)]
pub struct ServerListManager {
    http: ControlPlaneClient,
    storage: Arc<dyn Storage>,
}

impl std::fmt::Debug for ServerListManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ServerListManager").finish()
    }
}

impl ServerListManager {
    pub fn new(http: ControlPlaneClient, storage: Arc<dyn Storage>) -> Self {
        Self { http, storage }
    }

    /// Fetches the latest Firefox version string from Product Details (`firefox_versions.json`),
    /// falling back gracefully to [`DEFAULT_FIREFOX_VERSION`].
    pub async fn fetch_firefox_version(&self) -> String {
        let mut hdrs = HeaderMap::new();
        let ua = self.http.user_agent().await;
        apply_fxa_headers(&mut hdrs, &ua);
        let opts = RequestOptions::default();
        let Ok(resp) = self
            .http
            .execute(Method::GET, PRODUCT_DETAILS_URL, hdrs, Bytes::new(), opts)
            .await
        else {
            return DEFAULT_FIREFOX_VERSION.to_owned();
        };
        if !resp.status.is_success() {
            return DEFAULT_FIREFOX_VERSION.to_owned();
        }
        let Ok(v) = serde_json::from_slice::<serde_json::Value>(&resp.body) else {
            return DEFAULT_FIREFOX_VERSION.to_owned();
        };
        v.get("FIREFOX_NIGHTLY")
            .or_else(|| v.get("LATEST_FIREFOX_VERSION"))
            .and_then(|s| s.as_str())
            .filter(|s| !s.trim().is_empty())
            .unwrap_or(DEFAULT_FIREFOX_VERSION)
            .to_owned()
    }

    /// Fetches remote server records, falling back to cached `servers.json` if offline.
    pub async fn load_candidates(&self, env: &JexlEnv) -> Result<Vec<ProxyCandidate>, ServerListError> {
        Box::pin(async move {
            let raw = match self.fetch_remote_records().await {
                Ok(bytes) => {
                    let _ = self.storage.write(SERVERS_CACHE_FILE, &bytes).await;
                    bytes
                }
                Err(fetch_err) => {
                    tracing::debug!(error = %fetch_err, "using cached servers.json after remote fetch error");
                    self.storage
                        .read(SERVERS_CACHE_FILE)
                        .await
                        .map_err(|e| ServerListError::Fetch(e.to_string()))?
                        .ok_or(fetch_err)?
                }
            };

            parse_server_list_json(&raw, env)
        })
        .await
    }

    async fn fetch_remote_records(&self) -> Result<Vec<u8>, ServerListError> {
        Box::pin(async move {
            let mut hdrs = HeaderMap::new();
            let ua = self.http.user_agent().await;
            apply_fxa_headers(&mut hdrs, &ua);
            let opts = RequestOptions::default();
            let resp = self
                .http
                .execute(Method::GET, REMOTE_SETTINGS_URL, hdrs, Bytes::new(), opts)
                .await
                .map_err(ServerListError::Fetch)?;
            if !resp.status.is_success() {
                return Err(ServerListError::Fetch(format!(
                    "Remote Settings HTTP {}",
                    resp.status
                )));
            }
            Ok(resp.body.to_vec())
        })
        .await
    }

    /// Persists the chosen server selection into `selection.json`.
    pub async fn save_selection(&self, sel: &SelectionCache) {
        if let Ok(json) = serde_json::to_vec_pretty(sel) {
            let _ = self.storage.write(SELECTION_CACHE_FILE, &json).await;
        }
    }

    /// Loads previously saved selection metadata (`selection.json`).
    pub async fn load_selection(&self) -> Option<SelectionCache> {
        let bytes = self.storage.read(SELECTION_CACHE_FILE).await.ok().flatten()?;
        serde_json::from_slice(&bytes).ok()
    }
}

/// Parses Mozilla Remote Settings `vpn-serverlist` JSON and evaluates JEXL `filter_expression`s.
pub fn parse_server_list_json(
    raw: &[u8],
    env: &JexlEnv,
) -> Result<Vec<ProxyCandidate>, ServerListError> {
    let env_parsed: RemoteSettingsEnvelope = serde_json::from_slice(raw)?;
    let mut out = Vec::new();

    for rec in env_parsed.data {
        if rec.visible == Some(false) {
            continue;
        }
        if !rec.filter_expression.trim().is_empty()
            && !eval_jexl(&rec.filter_expression, env)?
        {
            continue;
        }

        let cc = if rec.country.trim().is_empty() {
            RECOMMENDED_COUNTRY_CODE.to_owned()
        } else {
            rec.country.trim().to_ascii_uppercase()
        };
        let cname = if rec.name.trim().is_empty() {
            cc.clone()
        } else {
            rec.name.trim().to_owned()
        };

        for srv in &rec.servers {
            if !srv.host.trim().is_empty() {
                out.push(ProxyCandidate {
                    country_code: cc.clone(),
                    country_name: cname.clone(),
                    city: rec.city.clone(),
                    host: srv.host.trim().to_owned(),
                    port: if srv.port == 0 { 443 } else { srv.port },
                    weight: srv.weight.max(1),
                });
            }
        }

        for city in &rec.cities {
            for srv in &city.servers {
                if !srv.host.trim().is_empty() {
                    out.push(ProxyCandidate {
                        country_code: cc.clone(),
                        country_name: cname.clone(),
                        city: if city.name.trim().is_empty() {
                            rec.city.clone()
                        } else {
                            city.name.trim().to_owned()
                        },
                        host: srv.host.trim().to_owned(),
                        port: if srv.port == 0 { 443 } else { srv.port },
                        weight: srv.weight.max(1),
                    });
                }
            }
        }
    }

    Ok(out)
}

/// Selects matching server candidates given config `country` (empty/REC/"recommended"/"fastest")
/// or pinned `server` (`host:port`).
pub fn select_candidates(
    all: &[ProxyCandidate],
    country: &str,
    pinned_server: &str,
) -> Result<Vec<ProxyCandidate>, ServerListError> {
    let server = pinned_server.trim();
    if !server.is_empty() {
        let (host, port) = crate::config::split_host_port(server).ok_or_else(|| {
            ServerListError::NoMatchingServers(format!("invalid pinned server {server:?}"))
        })?;
        if let Some(found) = all
            .iter()
            .find(|c| c.host.eq_ignore_ascii_case(host) && c.port == port)
        {
            return Ok(vec![found.clone()]);
        }
        return Ok(vec![ProxyCandidate {
            country_code: "CUSTOM".to_owned(),
            country_name: "Custom".to_owned(),
            city: String::new(),
            host: host.to_owned(),
            port,
            weight: 100,
        }]);
    }

    let c = country.trim();
    let mut matched: Vec<ProxyCandidate> = if c.is_empty()
        || c.eq_ignore_ascii_case(RECOMMENDED_COUNTRY_CODE)
        || c.eq_ignore_ascii_case("recommended")
    {
        let rec: Vec<_> = all
            .iter()
            .filter(|cand| cand.country_code.eq_ignore_ascii_case(RECOMMENDED_COUNTRY_CODE))
            .cloned()
            .collect();
        if rec.is_empty() {
            all.to_vec()
        } else {
            rec
        }
    } else if c.eq_ignore_ascii_case("fastest") {
        // Return non-REC endpoints first so latency prober can rank distinct regions.
        let mut distinct: Vec<_> = all
            .iter()
            .filter(|cand| !cand.country_code.eq_ignore_ascii_case(RECOMMENDED_COUNTRY_CODE))
            .cloned()
            .collect();
        if distinct.is_empty() {
            distinct = all.to_vec();
        }
        distinct
    } else {
        all.iter()
            .filter(|cand| {
                cand.country_code.eq_ignore_ascii_case(c)
                    || cand.country_name.eq_ignore_ascii_case(c)
            })
            .cloned()
            .collect()
    };

    if matched.is_empty() {
        return Err(ServerListError::NoMatchingServers(format!("country={country:?}")));
    }
    // Highest weight first; preserve order on ties.
    matched.sort_by_key(|a| std::cmp::Reverse(a.weight));
    Ok(matched)
}

/// Builds up to 3 standby failover candidates from non-failing countries in priority order
/// (`NL, DE, BE, FR, GB, AT`) plus remaining servers in `current_country` (`proxy/failover.go`).
pub fn build_standin_candidates(
    all: &[ProxyCandidate],
    current_country: &str,
    avoid: &std::collections::HashSet<String>,
) -> Vec<ProxyCandidate> {
    let mut out = Vec::new();
    let mut seen_addrs = std::collections::HashSet::new();

    for cand in all {
        if cand.country_code.eq_ignore_ascii_case(current_country) {
            let addr = cand.addr();
            if !avoid.contains(&addr) && seen_addrs.insert(addr) {
                out.push(cand.clone());
            }
        }
    }

    let mut fallback_countries = 0usize;
    for &cc in FAILOVER_STANDBY_COUNTRIES {
        if cc.eq_ignore_ascii_case(current_country) {
            continue;
        }
        if let Some(cand) = all
            .iter()
            .find(|c| c.country_code.eq_ignore_ascii_case(cc) && !avoid.contains(&c.addr()))
        {
            let addr = cand.addr();
            if seen_addrs.insert(addr) {
                out.push(cand.clone());
                fallback_countries += 1;
                if fallback_countries >= 3 {
                    break;
                }
            }
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Mozilla `nsIVersionComparator` & JEXL filter evaluator (`filter.go`, `version.go`)
// ---------------------------------------------------------------------------

/// Compares two Firefox/Toolkit version strings using Mozilla's `nsIVersionComparator` rules.
pub fn compare_versions(a: &str, b: &str) -> Ordering {
    let pa: Vec<&str> = a.trim().split('.').collect();
    let pb: Vec<&str> = b.trim().split('.').collect();
    let max_len = pa.len().max(pb.len());

    for i in 0..max_len {
        let sa = pa.get(i).copied().unwrap_or("");
        let sb = pb.get(i).copied().unwrap_or("");
        let ord = compare_version_part(sa, sb);
        if ord != Ordering::Equal {
            return ord;
        }
    }
    Ordering::Equal
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct VersionPart {
    num_a: i64,
    str_b: String,
    num_c: i64,
    extra_d: String,
}

fn parse_version_part(mut s: &str) -> VersionPart {
    if s.is_empty() {
        return VersionPart {
            num_a: 0,
            str_b: String::new(),
            num_c: 0,
            extra_d: String::new(),
        };
    }
    if s == "*" {
        return VersionPart {
            num_a: i64::MAX,
            str_b: String::new(),
            num_c: 0,
            extra_d: String::new(),
        };
    }

    let (num_a, rest) = take_leading_i64(s);
    s = rest;
    if let Some(after_plus) = s.strip_prefix('+') {
        return VersionPart {
            num_a: num_a + 1,
            str_b: "pre".to_owned(),
            num_c: 0,
            extra_d: after_plus.to_owned(),
        };
    }

    let split_b = s
        .find(|c: char| c.is_ascii_digit() || c == '+' || c == '-')
        .unwrap_or(s.len());
    let str_b = s[..split_b].to_owned();
    let s = &s[split_b..];
    let (num_c, rest2) = take_leading_i64(s);
    VersionPart {
        num_a,
        str_b,
        num_c,
        extra_d: rest2.to_owned(),
    }
}

fn take_leading_i64(s: &str) -> (i64, &str) {
    let mut end = 0usize;
    for (idx, ch) in s.char_indices() {
        if (idx == 0 && (ch == '-' || ch == '+')) || ch.is_ascii_digit() {
            end = idx + ch.len_utf8();
        } else {
            break;
        }
    }
    if end == 0 || (end == 1 && !s.as_bytes()[0].is_ascii_digit()) {
        return (0, s);
    }
    let val = s[..end].parse::<i64>().unwrap_or(0);
    (val, &s[end..])
}

fn compare_version_part(a: &str, b: &str) -> Ordering {
    let va = parse_version_part(a);
    let vb = parse_version_part(b);
    va.num_a
        .cmp(&vb.num_a)
        .then_with(|| cmp_ver_str(&va.str_b, &vb.str_b))
        .then_with(|| va.num_c.cmp(&vb.num_c))
        .then_with(|| cmp_ver_str(&va.extra_d, &vb.extra_d))
}

fn cmp_ver_str(a: &str, b: &str) -> Ordering {
    if a == b {
        return Ordering::Equal;
    }
    // Empty suffix > any non-empty pre-release suffix ("160.0" > "160.0a1").
    if a.is_empty() {
        return Ordering::Greater;
    }
    if b.is_empty() {
        return Ordering::Less;
    }
    a.cmp(b)
}

#[derive(Debug, Clone, PartialEq)]
enum JexlVal {
    Bool(bool),
    Int(i64),
    Str(String),
    List(Vec<JexlVal>),
}

impl JexlVal {
    fn truthy(&self) -> bool {
        match self {
            Self::Bool(b) => *b,
            Self::Int(i) => *i != 0,
            Self::Str(s) => !s.is_empty(),
            Self::List(l) => !l.is_empty(),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
enum Tok {
    And,
    Or,
    Not,
    Eq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
    In,
    Pipe,
    LParen,
    RParen,
    LBracket,
    RBracket,
    Comma,
    Ident(String),
    Str(String),
    Int(i64),
}

/// Evaluates a Mozilla Remote Settings JEXL `filter_expression` against [`JexlEnv`].
pub fn eval_jexl(expr: &str, env: &JexlEnv) -> Result<bool, ServerListError> {
    let tokens = tokenize_jexl(expr)?;
    if tokens.is_empty() {
        return Ok(true);
    }
    let mut parser = JexlParser {
        tokens: &tokens,
        pos: 0,
        env,
    };
    let val = parser.parse_or()?;
    if parser.pos < parser.tokens.len() {
        return Err(ServerListError::Filter(format!(
            "unexpected trailing token in {expr:?}"
        )));
    }
    Ok(val.truthy())
}

fn tokenize_jexl(expr: &str) -> Result<Vec<Tok>, ServerListError> {
    let mut out = Vec::new();
    let bytes = expr.as_bytes();
    let mut i = 0usize;

    while i < bytes.len() {
        let b = bytes[i];
        if b.is_ascii_whitespace() {
            i += 1;
            continue;
        }
        if expr[i..].starts_with("&&") {
            out.push(Tok::And);
            i += 2;
        } else if expr[i..].starts_with("||") {
            out.push(Tok::Or);
            i += 2;
        } else if expr[i..].starts_with("==") {
            out.push(Tok::Eq);
            i += 2;
        } else if expr[i..].starts_with("!=") {
            out.push(Tok::Ne);
            i += 2;
        } else if expr[i..].starts_with("<=") {
            out.push(Tok::Le);
            i += 2;
        } else if expr[i..].starts_with(">=") {
            out.push(Tok::Ge);
            i += 2;
        } else {
            match b {
                b'!' => {
                    out.push(Tok::Not);
                    i += 1;
                }
                b'<' => {
                    out.push(Tok::Lt);
                    i += 1;
                }
                b'>' => {
                    out.push(Tok::Gt);
                    i += 1;
                }
                b'|' => {
                    out.push(Tok::Pipe);
                    i += 1;
                }
                b'(' => {
                    out.push(Tok::LParen);
                    i += 1;
                }
                b')' => {
                    out.push(Tok::RParen);
                    i += 1;
                }
                b'[' => {
                    out.push(Tok::LBracket);
                    i += 1;
                }
                b']' => {
                    out.push(Tok::RBracket);
                    i += 1;
                }
                b',' => {
                    out.push(Tok::Comma);
                    i += 1;
                }
                b'\'' | b'"' => {
                    let quote = b;
                    i += 1;
                    let start = i;
                    while i < bytes.len() && bytes[i] != quote {
                        i += 1;
                    }
                    if i >= bytes.len() {
                        return Err(ServerListError::Filter("unterminated string literal".into()));
                    }
                    out.push(Tok::Str(expr[start..i].to_owned()));
                    i += 1;
                }
                c if c.is_ascii_digit() || (c == b'-' && bytes.get(i + 1).is_some_and(u8::is_ascii_digit)) => {
                    let start = i;
                    i += 1;
                    while i < bytes.len() && bytes[i].is_ascii_digit() {
                        i += 1;
                    }
                    let v = expr[start..i]
                        .parse::<i64>()
                        .map_err(|e| ServerListError::Filter(e.to_string()))?;
                    out.push(Tok::Int(v));
                }
                c if c.is_ascii_alphabetic() || c == b'_' => {
                    let start = i;
                    while i < bytes.len()
                        && (bytes[i].is_ascii_alphanumeric() || bytes[i] == b'_' || bytes[i] == b'.')
                    {
                        i += 1;
                    }
                    let word = &expr[start..i];
                    if word == "in" {
                        out.push(Tok::In);
                    } else {
                        out.push(Tok::Ident(word.to_owned()));
                    }
                }
                _ => {
                    return Err(ServerListError::Filter(format!(
                        "unexpected char {:?} in filter expression",
                        b as char
                    )));
                }
            }
        }
    }
    Ok(out)
}

struct JexlParser<'a> {
    tokens: &'a [Tok],
    pos: usize,
    env: &'a JexlEnv,
}

impl<'a> JexlParser<'a> {
    fn peek(&self) -> Option<&Tok> {
        self.tokens.get(self.pos)
    }

    fn next(&mut self) -> Option<Tok> {
        let t = self.tokens.get(self.pos)?.clone();
        self.pos += 1;
        Some(t)
    }

    fn parse_or(&mut self) -> Result<JexlVal, ServerListError> {
        let mut left = self.parse_and()?;
        while matches!(self.peek(), Some(Tok::Or)) {
            self.next();
            let right = self.parse_and()?;
            left = JexlVal::Bool(left.truthy() || right.truthy());
        }
        Ok(left)
    }

    fn parse_and(&mut self) -> Result<JexlVal, ServerListError> {
        let mut left = self.parse_cmp()?;
        while matches!(self.peek(), Some(Tok::And)) {
            self.next();
            let right = self.parse_cmp()?;
            left = JexlVal::Bool(left.truthy() && right.truthy());
        }
        Ok(left)
    }

    fn parse_cmp(&mut self) -> Result<JexlVal, ServerListError> {
        let left = self.parse_transform()?;
        let op = match self.peek() {
            Some(op @ (Tok::Eq | Tok::Ne | Tok::Lt | Tok::Le | Tok::Gt | Tok::Ge | Tok::In)) => {
                op.clone()
            }
            _ => return Ok(left),
        };
        self.next();
        let right = self.parse_transform()?;
        Ok(JexlVal::Bool(eval_cmp(&op, &left, &right)?))
    }

    fn parse_transform(&mut self) -> Result<JexlVal, ServerListError> {
        let mut val = self.parse_unary()?;
        while matches!(self.peek(), Some(Tok::Pipe)) {
            self.next();
            let Some(Tok::Ident(name)) = self.next() else {
                return Err(ServerListError::Filter("expected transform name after '|'".into()));
            };
            let mut args = Vec::new();
            if matches!(self.peek(), Some(Tok::LParen)) {
                self.next();
                if !matches!(self.peek(), Some(Tok::RParen)) {
                    loop {
                        args.push(self.parse_or()?);
                        if matches!(self.peek(), Some(Tok::Comma)) {
                            self.next();
                        } else {
                            break;
                        }
                    }
                }
                if !matches!(self.next(), Some(Tok::RParen)) {
                    return Err(ServerListError::Filter("expected ')' after transform args".into()));
                }
            }
            val = apply_transform(&name, val, &args)?;
        }
        Ok(val)
    }

    fn parse_unary(&mut self) -> Result<JexlVal, ServerListError> {
        if matches!(self.peek(), Some(Tok::Not)) {
            self.next();
            let v = self.parse_unary()?;
            return Ok(JexlVal::Bool(!v.truthy()));
        }
        self.parse_primary()
    }

    fn parse_primary(&mut self) -> Result<JexlVal, ServerListError> {
        let tok = self
            .next()
            .ok_or_else(|| ServerListError::Filter("unexpected end of filter expression".into()))?;
        match tok {
            Tok::LParen => {
                let v = self.parse_or()?;
                if !matches!(self.next(), Some(Tok::RParen)) {
                    return Err(ServerListError::Filter("missing ')'".into()));
                }
                Ok(v)
            }
            Tok::LBracket => {
                let mut items = Vec::new();
                if !matches!(self.peek(), Some(Tok::RBracket)) {
                    loop {
                        items.push(self.parse_or()?);
                        if matches!(self.peek(), Some(Tok::Comma)) {
                            self.next();
                        } else {
                            break;
                        }
                    }
                }
                if !matches!(self.next(), Some(Tok::RBracket)) {
                    return Err(ServerListError::Filter("missing ']'".into()));
                }
                Ok(JexlVal::List(items))
            }
            Tok::Str(s) => Ok(JexlVal::Str(s)),
            Tok::Int(i) => Ok(JexlVal::Int(i)),
            Tok::Ident(id) => match id.as_str() {
                "true" => Ok(JexlVal::Bool(true)),
                "false" => Ok(JexlVal::Bool(false)),
                "env.version" | "version" => Ok(JexlVal::Str(self.env.version.clone())),
                "env.appinfo.OS" | "env.os" => Ok(JexlVal::Str(self.env.os.clone())),
                "env.channel" | "env.appinfo.channel" => Ok(JexlVal::Str(self.env.channel.clone())),
                other => Ok(JexlVal::Str(
                    self.env.extra.get(other).cloned().unwrap_or_default(),
                )),
            },
            other => Err(ServerListError::Filter(format!("unexpected token {other:?}"))),
        }
    }
}

fn apply_transform(name: &str, val: JexlVal, args: &[JexlVal]) -> Result<JexlVal, ServerListError> {
    match name {
        "versionCompare" => {
            let lhs = match val {
                JexlVal::Str(s) => s,
                _ => return Err(ServerListError::Filter("versionCompare expects string lhs".into())),
            };
            let rhs = match args.first() {
                Some(JexlVal::Str(s)) => s.as_str(),
                _ => return Err(ServerListError::Filter("versionCompare expects string arg".into())),
            };
            let ord = compare_versions(&lhs, rhs);
            let i = match ord {
                Ordering::Less => -1,
                Ordering::Equal => 0,
                Ordering::Greater => 1,
            };
            Ok(JexlVal::Int(i))
        }
        "lower" => match val {
            JexlVal::Str(s) => Ok(JexlVal::Str(s.to_ascii_lowercase())),
            other => Ok(other),
        },
        other => Err(ServerListError::Filter(format!("unsupported JEXL transform {other:?}"))),
    }
}

fn eval_cmp(op: &Tok, lhs: &JexlVal, rhs: &JexlVal) -> Result<bool, ServerListError> {
    match op {
        Tok::Eq => Ok(lhs == rhs),
        Tok::Ne => Ok(lhs != rhs),
        Tok::In => match rhs {
            JexlVal::List(items) => Ok(items.contains(lhs)),
            JexlVal::Str(haystack) => match lhs {
                JexlVal::Str(needle) => Ok(haystack.contains(needle.as_str())),
                _ => Ok(false),
            },
            _ => Ok(false),
        },
        Tok::Lt | Tok::Le | Tok::Gt | Tok::Ge => {
            let ord = match (lhs, rhs) {
                (JexlVal::Int(a), JexlVal::Int(b)) => a.cmp(b),
                (JexlVal::Str(a), JexlVal::Str(b)) => a.cmp(b),
                _ => {
                    return Err(ServerListError::Filter(
                        "relational comparison requires matching int/string types".into(),
                    ));
                }
            };
            Ok(match op {
                Tok::Lt => ord == Ordering::Less,
                Tok::Le => ord != Ordering::Greater,
                Tok::Gt => ord == Ordering::Greater,
                Tok::Ge => ord != Ordering::Less,
                _ => false,
            })
        }
        _ => Ok(false),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compares_mozilla_versions_correctly() {
        assert_eq!(compare_versions("160.0", "160.0a1"), Ordering::Greater);
        assert_eq!(compare_versions("160.0a1", "160.0a2"), Ordering::Less);
        assert_eq!(compare_versions("158.0", "158.0.0"), Ordering::Equal);
        assert_eq!(compare_versions("159.0", "158.9"), Ordering::Greater);
    }

    #[test]
    fn evaluates_jexl_filter_expressions() {
        let env = JexlEnv {
            version: "160.0a1".into(),
            os: "WINNT".into(),
            channel: "nightly".into(),
            extra: HashMap::new(),
        };
        assert!(
            eval_jexl(
                "env.version|versionCompare('134.0!') >= 0 && env.appinfo.OS in ['WINNT', 'Linux']",
                &env
            )
            .unwrap()
        );
        assert!(!eval_jexl("env.version|versionCompare('161.0') >= 0", &env).unwrap());
    }

    #[test]
    fn parses_remote_settings_and_selects_candidates() {
        let json = br#"{
          "data": [
            {
              "country": "REC",
              "name": "Recommended",
              "servers": [{"host": "nl-rec.example", "port": 443, "weight": 100}],
              "filter_expression": "env.version|versionCompare('134.0!') >= 0"
            },
            {
              "country": "DE",
              "name": "Germany",
              "cities": [{"name": "Frankfurt", "servers": [{"host": "de-fra.example", "port": 443, "weight": 50}]}],
              "filter_expression": ""
            },
            {
              "country": "FR",
              "name": "FutureOnly",
              "servers": [{"host": "fr-future.example", "port": 443}],
              "filter_expression": "env.version|versionCompare('999.0') >= 0"
            }
          ]
        }"#;
        let cands = parse_server_list_json(json, &JexlEnv::default()).unwrap();
        assert_eq!(cands.len(), 2);

        let rec = select_candidates(&cands, "", "").unwrap();
        assert_eq!(rec.len(), 1);
        assert_eq!(rec[0].host, "nl-rec.example");

        let de = select_candidates(&cands, "Germany", "").unwrap();
        assert_eq!(de[0].host, "de-fra.example");
        assert_eq!(de[0].city, "Frankfurt");
    }
}
