//! Persistent daemon configuration schema, defaults, validation, and storage loading.

use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;
use std::time::Duration;

use base64::Engine as _;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::error::ConfigError;
use crate::hellosplit::HelloSplitMode;
use crate::storage::Storage;

/// Current configuration schema version written by this build.
pub const CURRENT_VERSION: u32 = 2;

/// Default filename inside the storage backend / data directory.
pub const CONFIG_FILE_NAME: &str = "config.json";

/// Default local SOCKS5/HTTP listener address (`sing-box` upstream target).
pub const DEFAULT_PROXY_LISTEN: &str = "127.0.0.1:10810";

/// Default account quota percentage before automatic failover.
pub const DEFAULT_SWITCH_THRESHOLD_PERCENT: f64 = 95.0;

/// Default Guardian API endpoint.
pub const DEFAULT_GUARDIAN_ENDPOINT: &str = "https://vpn.mozilla.org";

/// Default runtime timeouts.
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(20);
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
pub const IDLE_TIMEOUT: Option<Duration> = None;
pub const EXIT_CHECK_TIMEOUT: Duration = Duration::from_secs(20);
pub const DEFAULT_IDLE_SLEEP: Duration = Duration::from_secs(15 * 60);

/// Default bootstrap DoH servers used for `heartburn`'s own lookups.
pub fn default_dns_servers() -> Vec<String> {
    vec![
        "https://1.1.1.1/dns-query".to_owned(),
        "https://8.8.8.8/dns-query".to_owned(),
        "https://9.9.9.9/dns-query".to_owned(),
    ]
}

/// Allowed upstream proxy transports.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TransportKind {
    #[default]
    H2,
    H3,
    H1,
}

impl TransportKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::H2 => "h2",
            Self::H3 => "h3",
            Self::H1 => "h1",
        }
    }
}

impl FromStr for TransportKind {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_ascii_lowercase().as_str() {
            "h2" => Ok(Self::H2),
            "h3" => Ok(Self::H3),
            "h1" => Ok(Self::H1),
            other => Err(format!("expected \"h2\", \"h3\", or \"h1\", got {other:?}")),
        }
    }
}

/// Upstream IP family preference for connections to Mozilla Fastly edges.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IpVersionMode {
    #[default]
    Auto,
    Dual,
    Ipv6First,
    Ipv4,
    Ipv6,
}

impl IpVersionMode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::Dual => "dual",
            Self::Ipv6First => "ipv6_first",
            Self::Ipv4 => "ipv4",
            Self::Ipv6 => "ipv6",
        }
    }
}

impl FromStr for IpVersionMode {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_ascii_lowercase().as_str() {
            "" | "auto" => Ok(Self::Auto),
            "dual" => Ok(Self::Dual),
            "ipv6_first" => Ok(Self::Ipv6First),
            "ipv4" => Ok(Self::Ipv4),
            "ipv6" => Ok(Self::Ipv6),
            other => Err(format!(
                "expected auto, dual, ipv6_first, ipv4, or ipv6, got {other:?}"
            )),
        }
    }
}

/// ECH mode for `network.api_relay_ech`.
pub const RELAY_ECH_OFF: &str = "off";
pub const RELAY_ECH_ON: &str = "on";
pub const RELAY_ECH_REQUIRE: &str = "require";

/// Duration encoded as a Go-compatible duration string (`"15m0s"`, `"10s"`, `"0s"`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct GoDuration(pub Duration);

impl GoDuration {
    pub const fn from_secs(secs: u64) -> Self {
        Self(Duration::from_secs(secs))
    }

    pub const fn as_duration(self) -> Duration {
        self.0
    }

    pub const fn is_zero(self) -> bool {
        self.0.is_zero()
    }
}

impl From<Duration> for GoDuration {
    fn from(d: Duration) -> Self {
        Self(d)
    }
}

impl From<GoDuration> for Duration {
    fn from(d: GoDuration) -> Self {
        d.0
    }
}

impl Serialize for GoDuration {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&format_go_duration(self.0))
    }
}

impl<'de> Deserialize<'de> for GoDuration {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        parse_go_duration(&s)
            .map(GoDuration)
            .map_err(serde::de::Error::custom)
    }
}

/// Formats a `Duration` in Go's canonical `time.Duration.String()` syntax.
pub fn format_go_duration(d: Duration) -> String {
    if d.is_zero() {
        return "0s".to_owned();
    }
    let total_nanos = d.as_nanos();
    if total_nanos < 1_000 {
        return format!("{total_nanos}ns");
    }
    if total_nanos < 1_000_000 {
        let us = total_nanos as f64 / 1_000.0;
        return format!("{us}µs");
    }
    if total_nanos < 1_000_000_000 {
        let ms = total_nanos / 1_000_000;
        let rem = total_nanos % 1_000_000;
        if rem == 0 {
            return format!("{ms}ms");
        }
        return format!("{:.3}ms", total_nanos as f64 / 1_000_000.0);
    }
    let mut secs = d.as_secs();
    let nanos = d.subsec_nanos();
    let hours = secs / 3600;
    secs %= 3600;
    let mins = secs / 60;
    secs %= 60;

    let mut out = String::new();
    if hours > 0 {
        out.push_str(&format!("{hours}h"));
    }
    if hours > 0 || mins > 0 {
        out.push_str(&format!("{mins}m"));
    }
    if nanos == 0 {
        out.push_str(&format!("{secs}s"));
    } else {
        let frac = format!("{nanos:09}");
        let trimmed = frac.trim_end_matches('0');
        out.push_str(&format!("{secs}.{trimmed}s"));
    }
    out
}

/// Parses a Go-style duration string (`"0"`, `"0s"`, `"15m0s"`, `"1h30m"`, `"250ms"`).
pub fn parse_go_duration(raw: &str) -> Result<Duration, ConfigError> {
    let s = raw.trim();
    if s.is_empty() {
        return Err(ConfigError::InvalidDuration(raw.to_owned()));
    }
    if s == "0" {
        return Ok(Duration::ZERO);
    }
    if s.starts_with('-') {
        return Err(ConfigError::InvalidDuration(raw.to_owned()));
    }

    let bytes = s.as_bytes();
    let mut i = 0usize;
    let mut total_nanos: u128 = 0;

    while i < bytes.len() {
        let num_start = i;
        let mut saw_digit = false;
        let mut saw_dot = false;
        while i < bytes.len() {
            let b = bytes[i];
            if b.is_ascii_digit() {
                saw_digit = true;
                i += 1;
            } else if b == b'.' && !saw_dot {
                saw_dot = true;
                i += 1;
            } else {
                break;
            }
        }
        if !saw_digit {
            return Err(ConfigError::InvalidDuration(raw.to_owned()));
        }
        let num_str = &s[num_start..i];
        let val: f64 = num_str
            .parse()
            .map_err(|_| ConfigError::InvalidDuration(raw.to_owned()))?;

        let unit_start = i;
        while i < s.len() {
            let ch = s[i..].chars().next().ok_or_else(|| ConfigError::InvalidDuration(raw.to_owned()))?;
            if ch.is_ascii_digit() || ch == '.' {
                break;
            }
            i += ch.len_utf8();
        }
        let unit = &s[unit_start..i];
        let mult_ns: f64 = match unit {
            "ns" => 1.0,
            "us" | "µs" | "μs" => 1_000.0,
            "ms" => 1_000_000.0,
            "s" => 1_000_000_000.0,
            "m" => 60.0 * 1_000_000_000.0,
            "h" => 3600.0 * 1_000_000_000.0,
            _ => return Err(ConfigError::InvalidDuration(raw.to_owned())),
        };
        let term = val * mult_ns;
        if !term.is_finite() || term < 0.0 || term > u128::MAX as f64 {
            return Err(ConfigError::InvalidDuration(raw.to_owned()));
        }
        total_nanos = total_nanos
            .checked_add(term.round() as u128)
            .ok_or_else(|| ConfigError::InvalidDuration(raw.to_owned()))?;
    }

    let secs = (total_nanos / 1_000_000_000) as u64;
    let subsec_nanos = (total_nanos % 1_000_000_000) as u32;
    Ok(Duration::new(secs, subsec_nanos))
}

/// Complete lean `heartburn` configuration.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    pub version: u32,
    pub proxy: ProxyConfig,
    pub accounts: AccountsConfig,
    pub network: NetworkConfig,
    pub dns: DnsConfig,
    pub logging: LoggingConfig,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            version: CURRENT_VERSION,
            proxy: ProxyConfig::default(),
            accounts: AccountsConfig::default(),
            network: NetworkConfig::default(),
            dns: DnsConfig::default(),
            logging: LoggingConfig::default(),
        }
    }
}

/// Local inbound SOCKS5/HTTP listener and Mozilla upstream selection settings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct ProxyConfig {
    pub listen: String,
    pub username: String,
    pub password: String,
    pub country: String,
    pub server: String,
    pub transport: String,
    #[serde(default)]
    pub ip_version: String,
    pub upstream_connections: usize,
    pub max_connections: usize,
    pub idle_sleep: GoDuration,
}

impl Default for ProxyConfig {
    fn default() -> Self {
        Self {
            listen: DEFAULT_PROXY_LISTEN.to_owned(),
            username: String::new(),
            password: String::new(),
            country: String::new(),
            server: String::new(),
            transport: "h2".to_owned(),
            ip_version: "auto".to_owned(),
            upstream_connections: 1,
            max_connections: 256,
            idle_sleep: GoDuration(DEFAULT_IDLE_SLEEP),
        }
    }
}

/// Multi-account failover configuration.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct AccountsConfig {
    pub switch_threshold_percent: f64,
    pub order: Vec<AccountRef>,
}

impl Default for AccountsConfig {
    fn default() -> Self {
        Self {
            switch_threshold_percent: DEFAULT_SWITCH_THRESHOLD_PERCENT,
            order: Vec::new(),
        }
    }
}

/// Priority entry referencing an account ID in storage.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccountRef {
    pub id: String,
    pub enabled: bool,
}

/// Control-plane circumvention and upstream relay/proxy settings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct NetworkConfig {
    pub api_relay: String,
    pub api_relay_enabled: bool,
    pub shared_relay_enabled: bool,
    pub api_relay_ech: String,
    pub api_relay_ech_config: String,
    pub guardian_endpoint: String,
    pub hello_split: String,
    pub upstream_proxy_enabled: bool,
    pub upstream_proxy: String,
    pub upstream_proxy_username: String,
    pub upstream_proxy_password: String,
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            api_relay: String::new(),
            api_relay_enabled: true,
            shared_relay_enabled: true,
            api_relay_ech: RELAY_ECH_ON.to_owned(),
            api_relay_ech_config: String::new(),
            guardian_endpoint: DEFAULT_GUARDIAN_ENDPOINT.to_owned(),
            hello_split: HelloSplitMode::Auto.as_str().to_owned(),
            upstream_proxy_enabled: false,
            upstream_proxy: String::new(),
            upstream_proxy_username: String::new(),
            upstream_proxy_password: String::new(),
        }
    }
}

impl NetworkConfig {
    /// Returns the enabled upstream SOCKS5 address, or `""` when disabled.
    pub fn upstream_proxy_in_use(&self) -> &str {
        if self.upstream_proxy_enabled {
            self.upstream_proxy.trim()
        } else {
            ""
        }
    }

    /// Returns the enabled personal API relay URL, or `""` when disabled.
    pub fn api_relay_in_use(&self) -> &str {
        if self.api_relay_enabled {
            self.api_relay.trim()
        } else {
            ""
        }
    }

    /// Returns `true` when shared relay pool is allowed and no personal relay overrides it.
    pub fn shared_relay_in_use(&self) -> bool {
        self.shared_relay_enabled && self.api_relay_in_use().is_empty()
    }
}

/// Bootstrap DNS configuration for `heartburn`'s own upstream lookups.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct DnsConfig {
    pub servers: Vec<String>,
    pub fallback_to_system: bool,
}

impl Default for DnsConfig {
    fn default() -> Self {
        Self {
            servers: default_dns_servers(),
            fallback_to_system: true,
        }
    }
}

/// Logging verbosity settings.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct LoggingConfig {
    pub verbose: bool,
}

/// Cleans pasted upstream proxy strings (strips whitespace, optional scheme, trailing slash).
pub fn clean_upstream_proxy(raw: &str) -> String {
    let no_ws: String = raw.split_whitespace().collect();
    let without_scheme = match no_ws.split_once("://") {
        Some((_, rest)) => rest,
        None => no_ws.as_str(),
    };
    without_scheme.trim_end_matches('/').to_owned()
}

/// Normalizes an updated [`NetworkConfig`] relative to `prev`, auto-enabling the
/// upstream proxy when newly populated and disabling it when cleared.
pub fn settle_upstream_proxy(prev: &NetworkConfig, mut next: NetworkConfig) -> NetworkConfig {
    next.upstream_proxy = clean_upstream_proxy(&next.upstream_proxy);
    next.upstream_proxy_username = next.upstream_proxy_username.trim().to_owned();
    next.upstream_proxy_password = next.upstream_proxy_password.trim().to_owned();
    if next.upstream_proxy.is_empty() {
        next.upstream_proxy_enabled = false;
    } else if prev.upstream_proxy.trim().is_empty() {
        next.upstream_proxy_enabled = true;
    }
    next
}

/// Validates an API relay URL: empty, or `https://` with non-empty host.
pub fn validate_relay_url(raw: &str) -> Result<(), ConfigError> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Ok(());
    }
    let u = url::Url::parse(trimmed).map_err(|e| ConfigError::Validation {
        field: "network.api_relay",
        message: e.to_string(),
    })?;
    if u.scheme() != "https" || u.host_str().unwrap_or_default().is_empty() {
        return Err(ConfigError::Validation {
            field: "network.api_relay",
            message: "must be an https:// URL (auth and tokens cross it)".into(),
        });
    }
    Ok(())
}

/// Parsed ECH key source from `network.api_relay_ech_config`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EchSource {
    /// Use the relay host's own HTTPS DNS record.
    RelayHost,
    /// Query the HTTPS DNS record of the named host (e.g., `cloudflare-ech.com`).
    DnsName(String),
    /// Explicit decoded raw ECHConfigList bytes.
    RawConfigList(Vec<u8>),
}

/// Parses `network.api_relay_ech_config` into DNS name, explicit raw ECHConfigList, or `RelayHost`.
pub fn parse_ech_source(raw: &str) -> Result<EchSource, ConfigError> {
    let s = raw.trim();
    if s.is_empty() {
        return Ok(EchSource::RelayHost);
    }

    if s.contains('.') && !s.contains(['/', '+', '=']) {
        let name = s.to_ascii_lowercase().trim_end_matches('.').to_owned();
        let valid = !name.is_empty()
            && name.split('.').all(|label| {
                !label.is_empty()
                    && label.len() <= 63
                    && label
                        .bytes()
                        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_')
            });
        if !valid {
            return Err(ConfigError::Validation {
                field: "network.api_relay_ech_config",
                message: format!("{raw:?} is not a valid DNS name"),
            });
        }
        return Ok(EchSource::DnsName(name));
    }

    let decoded = decode_any_base64(s).ok_or_else(|| ConfigError::Validation {
        field: "network.api_relay_ech_config",
        message: "neither a DNS name nor valid base64".into(),
    })?;

    if decoded.len() < 2 {
        return Err(ConfigError::Validation {
            field: "network.api_relay_ech_config",
            message: "ECHConfigList too short".into(),
        });
    }
    let declared = u16::from_be_bytes([decoded[0], decoded[1]]) as usize;
    if declared != decoded.len() - 2 {
        return Err(ConfigError::Validation {
            field: "network.api_relay_ech_config",
            message: "neither a DNS name nor an ECHConfigList in base64".into(),
        });
    }
    Ok(EchSource::RawConfigList(decoded))
}

fn decode_any_base64(s: &str) -> Option<Vec<u8>> {
    use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD};
    STANDARD
        .decode(s)
        .or_else(|_| STANDARD_NO_PAD.decode(s))
        .or_else(|_| URL_SAFE.decode(s))
        .or_else(|_| URL_SAFE_NO_PAD.decode(s))
        .ok()
}

/// Splits a `host:port` string (supporting IPv6 brackets `[::1]:10810` or `:10810`).
pub fn split_host_port(addr: &str) -> Option<(&str, u16)> {
    let trimmed = addr.trim();
    if let Ok(sock) = trimmed.parse::<SocketAddr>() {
        // Return slice inside trimmed excluding brackets for IPv6 if present.
        if let Some(rest) = trimmed.strip_prefix('[') {
            if let Some((host, _)) = rest.split_once("]:") {
                return Some((host, sock.port()));
            }
        } else if let Some((host, _)) = trimmed.rsplit_once(':') {
            return Some((host, sock.port()));
        }
    }
    let (host_raw, port_str) = trimmed.rsplit_once(':')?;
    if host_raw.contains(':') && !(host_raw.starts_with('[') && host_raw.ends_with(']')) {
        return None;
    }
    let port: u16 = port_str.parse().ok()?;
    if port == 0 {
        return None;
    }
    let host = host_raw
        .strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(host_raw);
    Some((host, port))
}

fn validate_listen(field: &'static str, addr: &str) -> Result<(), ConfigError> {
    let Some((host, port)) = split_host_port(addr) else {
        return Err(ConfigError::Validation {
            field,
            message: format!("{addr:?} must be host:port with port 1..=65535"),
        });
    };
    if port == 0 {
        return Err(ConfigError::Validation {
            field,
            message: format!("{addr:?} has invalid port 0"),
        });
    }
    if !host.is_empty() && !host.eq_ignore_ascii_case("localhost") && host.parse::<IpAddr>().is_err()
    {
        return Err(ConfigError::Validation {
            field,
            message: format!("{addr:?} must be an IP address (or localhost) and port"),
        });
    }
    Ok(())
}

/// Validates every DNS server specification (`https://`, `tls://`, or IP[:port]).
pub fn validate_dns_servers(servers: &[String]) -> Result<(), ConfigError> {
    for raw in servers {
        let s = raw.trim();
        if s.is_empty() {
            return Err(ConfigError::Validation {
                field: "dns.servers",
                message: "empty DNS server entry".into(),
            });
        }
        if s.starts_with("https://") {
            let u = url::Url::parse(s).map_err(|e| ConfigError::Validation {
                field: "dns.servers",
                message: format!("{s:?}: {e}"),
            })?;
            if u.host_str().unwrap_or_default().is_empty() {
                return Err(ConfigError::Validation {
                    field: "dns.servers",
                    message: format!("{s:?} missing host"),
                });
            }
        } else if let Some(rest) = s.strip_prefix("tls://") {
            let host = if let Some((h, _port)) = split_host_port(rest) {
                h
            } else {
                rest.trim_matches(['[', ']'])
            };
            if host.is_empty() {
                return Err(ConfigError::Validation {
                    field: "dns.servers",
                    message: format!("{s:?} missing host"),
                });
            }
        } else if s.parse::<IpAddr>().is_ok() {
            continue;
        } else if let Some((host, _port)) = split_host_port(s) {
            if host.parse::<IpAddr>().is_err() {
                return Err(ConfigError::Validation {
                    field: "dns.servers",
                    message: format!("{s:?} must use an IP address for plain DNS"),
                });
            }
        } else {
            return Err(ConfigError::Validation {
                field: "dns.servers",
                message: format!("{s:?} is not https://, tls://, or an IP[:port]"),
            });
        }
    }
    Ok(())
}

/// Validates upstream SOCKS5 coordinates against our own listen port to avoid loops.
pub fn validate_upstream_proxy(n: &NetworkConfig, listen: &str) -> Result<(), ConfigError> {
    if n.upstream_proxy.trim().is_empty() {
        return Ok(());
    }
    let Some((host, port)) = split_host_port(&n.upstream_proxy) else {
        return Err(ConfigError::Validation {
            field: "network.upstream_proxy",
            message: format!("{:?} is not host:port", n.upstream_proxy),
        });
    };
    if host.is_empty() {
        return Err(ConfigError::Validation {
            field: "network.upstream_proxy",
            message: format!("{:?} missing host", n.upstream_proxy),
        });
    }
    if n.upstream_proxy_username.is_empty() != n.upstream_proxy_password.is_empty() {
        return Err(ConfigError::Validation {
            field: "network.upstream_proxy",
            message: "username and password must be set together".into(),
        });
    }
    if n.upstream_proxy_username.len() > 255 || n.upstream_proxy_password.len() > 255 {
        return Err(ConfigError::Validation {
            field: "network.upstream_proxy",
            message: "SOCKS5 username and password cannot exceed 255 bytes".into(),
        });
    }

    let is_local = host.eq_ignore_ascii_case("localhost")
        || host
            .parse::<IpAddr>()
            .map(|ip| ip.is_loopback() || ip.is_unspecified())
            .unwrap_or(false);
    if n.upstream_proxy_enabled
        && is_local
        && let Some((_, own_port)) = split_host_port(listen)
        && own_port == port
    {
        return Err(ConfigError::Validation {
            field: "network.upstream_proxy",
            message: format!("{} points to heartburn's own proxy listener", n.upstream_proxy),
        });
    }
    Ok(())
}

impl Config {
    /// Returns the parsed upstream transport kind.
    pub fn transport_kind(&self) -> Result<TransportKind, ConfigError> {
        self.proxy
            .transport
            .parse()
            .map_err(|msg| ConfigError::Validation {
                field: "proxy.transport",
                message: msg,
            })
    }

    /// Returns the parsed IP version preference.
    pub fn ip_version_mode(&self) -> Result<IpVersionMode, ConfigError> {
        self.proxy
            .ip_version
            .parse()
            .map_err(|msg| ConfigError::Validation {
                field: "proxy.ip_version",
                message: msg,
            })
    }

    /// Returns the parsed HelloSplit mode.
    pub fn hello_split_mode(&self) -> Result<HelloSplitMode, ConfigError> {
        self.network
            .hello_split
            .parse()
            .map_err(|msg| ConfigError::Validation {
                field: "network.hello_split",
                message: msg,
            })
    }

    /// Validates all configuration invariants.
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.version > CURRENT_VERSION {
            return Err(ConfigError::Validation {
                field: "version",
                message: format!(
                    "config version {} is newer than supported version {}",
                    self.version, CURRENT_VERSION
                ),
            });
        }

        let p = &self.proxy;
        validate_listen("proxy.listen", &p.listen)?;
        if p.username.is_empty() != p.password.is_empty() {
            return Err(ConfigError::Validation {
                field: "proxy.username",
                message: "proxy.username and proxy.password must be set together".into(),
            });
        }
        if p.username.len() > 255 || p.password.len() > 255 {
            return Err(ConfigError::Validation {
                field: "proxy.username",
                message: "limited to 255 bytes".into(),
            });
        }
        if !p.country.trim().is_empty() && !p.server.trim().is_empty() {
            return Err(ConfigError::Validation {
                field: "proxy.country",
                message: "proxy.country and proxy.server are mutually exclusive".into(),
            });
        }
        if !p.server.trim().is_empty() && split_host_port(&p.server).is_none() {
            return Err(ConfigError::Validation {
                field: "proxy.server",
                message: format!("{:?} must be host:port", p.server),
            });
        }
        let _ = self.transport_kind()?;
        let _ = self.ip_version_mode()?;

        if p.upstream_connections < 1 {
            return Err(ConfigError::Validation {
                field: "proxy.upstream_connections",
                message: "must be at least 1".into(),
            });
        }
        if !p.idle_sleep.is_zero() && p.idle_sleep.as_duration() < Duration::from_secs(60) {
            return Err(ConfigError::Validation {
                field: "proxy.idle_sleep",
                message: "must be 0s (off) or at least 1m".into(),
            });
        }

        let a = &self.accounts;
        if !(a.switch_threshold_percent > 0.0 && a.switch_threshold_percent <= 100.0) {
            return Err(ConfigError::Validation {
                field: "accounts.switch_threshold_percent",
                message: "must be > 0 and <= 100".into(),
            });
        }
        let mut seen = std::collections::HashSet::with_capacity(a.order.len());
        for r in &a.order {
            if r.id.trim().is_empty() {
                return Err(ConfigError::Validation {
                    field: "accounts.order",
                    message: "contains an empty id".into(),
                });
            }
            if !seen.insert(r.id.as_str()) {
                return Err(ConfigError::Validation {
                    field: "accounts.order",
                    message: format!("lists {:?} twice", r.id),
                });
            }
        }

        validate_dns_servers(&self.dns.servers)?;
        validate_relay_url(&self.network.api_relay)?;

        match self.network.api_relay_ech.trim() {
            "" | RELAY_ECH_OFF | RELAY_ECH_ON | RELAY_ECH_REQUIRE => {}
            other => {
                return Err(ConfigError::Validation {
                    field: "network.api_relay_ech",
                    message: format!("{other:?} is not off, on, or require"),
                });
            }
        }
        let _ = parse_ech_source(&self.network.api_relay_ech_config)?;
        let _ = self.hello_split_mode()?;

        let guardian = self.network.guardian_endpoint.trim();
        if guardian.is_empty() || !guardian.starts_with("https://") {
            return Err(ConfigError::Validation {
                field: "network.guardian_endpoint",
                message: "must be an https:// URL".into(),
            });
        }

        validate_upstream_proxy(&self.network, &p.listen)?;
        Ok(())
    }

    /// Normalizes runtime fields (`"REC"`/`"recommended"` country -> `""`, clean proxy string).
    pub fn normalize(&mut self) -> bool {
        let mut changed = false;
        let c = self.proxy.country.trim();
        if c.eq_ignore_ascii_case("REC") || c.eq_ignore_ascii_case("recommended") {
            self.proxy.country.clear();
            changed = true;
        }
        let cleaned = clean_upstream_proxy(&self.network.upstream_proxy);
        if cleaned != self.network.upstream_proxy {
            self.network.upstream_proxy = cleaned;
            changed = true;
        }
        if self.network.guardian_endpoint.trim().is_empty() {
            self.network.guardian_endpoint = DEFAULT_GUARDIAN_ENDPOINT.to_owned();
            changed = true;
        }
        if self.version < CURRENT_VERSION {
            self.version = CURRENT_VERSION;
            changed = true;
        }
        changed
    }

    /// Loads `config.json` from `storage`, creating defaults if missing or recovering
    /// syntactically invalid/truncated JSON files as `config.json.corrupt`.
    pub async fn load_from(storage: &dyn Storage) -> Result<(Self, bool), ConfigError> {
        let Some(raw) = storage.read(CONFIG_FILE_NAME).await? else {
            let cfg = Self::default();
            cfg.save_to(storage).await?;
            return Ok((cfg, true));
        };

        let mut cfg: Self = match serde_json::from_slice(&raw) {
            Ok(parsed) => parsed,
            Err(parse_err) => {
                // Only auto-reset if the file isn't even valid JSON syntax (e.g. crash truncation).
                if serde_json::from_slice::<serde_json::Value>(&raw).is_err() {
                    if raw.iter().any(|b| !b.is_ascii_whitespace()) {
                        storage
                            .write(&format!("{CONFIG_FILE_NAME}.corrupt"), &raw)
                            .await?;
                    }
                    tracing::warn!(
                        error = %parse_err,
                        "config.json could not be parsed; preserved corrupt file and reset to defaults"
                    );
                    let cfg = Self::default();
                    cfg.save_to(storage).await?;
                    return Ok((cfg, true));
                }
                return Err(ConfigError::Json(parse_err));
            }
        };

        let normalized = cfg.normalize();
        cfg.validate()?;
        if normalized {
            cfg.save_to(storage).await?;
        }
        Ok((cfg, false))
    }

    /// Saves this configuration cleanly formatted to `storage`.
    pub async fn save_to(&self, storage: &dyn Storage) -> Result<(), ConfigError> {
        let mut to_write = self.clone();
        to_write.version = CURRENT_VERSION;
        let mut json = serde_json::to_vec_pretty(&to_write)?;
        json.push(b'\n');
        storage.write(CONFIG_FILE_NAME, &json).await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::MemoryStorage;

    #[test]
    fn duration_roundtrip_and_parse() {
        assert_eq!(format_go_duration(Duration::ZERO), "0s");
        assert_eq!(format_go_duration(Duration::from_secs(900)), "15m0s");
        assert_eq!(format_go_duration(Duration::from_secs(3661)), "1h1m1s");

        assert_eq!(parse_go_duration("0").unwrap(), Duration::ZERO);
        assert_eq!(parse_go_duration("15m0s").unwrap(), Duration::from_secs(900));
        assert_eq!(parse_go_duration("1h30m").unwrap(), Duration::from_secs(5400));
        assert_eq!(parse_go_duration("250ms").unwrap(), Duration::from_millis(250));
        assert!(parse_go_duration("-5s").is_err());
    }

    #[test]
    fn default_config_is_valid() {
        let cfg = Config::default();
        cfg.validate().unwrap();
        assert_eq!(cfg.proxy.listen, "127.0.0.1:10810");
        assert_eq!(cfg.proxy.transport, "h2");
        assert_eq!(cfg.dns.servers.len(), 3);
    }

    #[test]
    fn validation_catches_invalid_settings() {
        let mut cfg = Config::default();
        cfg.proxy.country = "nl".into();
        cfg.proxy.server = "example.com:443".into();
        assert!(cfg.validate().is_err());

        let mut cfg = Config::default();
        cfg.network.api_relay = "http://insecure.example".into();
        assert!(cfg.validate().is_err());

        let mut cfg = Config::default();
        cfg.network.upstream_proxy = "socks5://127.0.0.1:10810/".into();
        cfg.network = settle_upstream_proxy(&NetworkConfig::default(), cfg.network);
        assert!(cfg.network.upstream_proxy_enabled);
        assert_eq!(cfg.network.upstream_proxy, "127.0.0.1:10810");
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn parses_ech_source_variants() {
        assert_eq!(parse_ech_source("").unwrap(), EchSource::RelayHost);
        assert_eq!(
            parse_ech_source("cloudflare-ech.com.").unwrap(),
            EchSource::DnsName("cloudflare-ech.com".into())
        );
        // Valid ECHConfigList: 2-byte big-endian length (4) + 4 bytes payload.
        let b64 = base64::engine::general_purpose::STANDARD.encode([0, 4, 1, 2, 3, 4]);
        assert_eq!(
            parse_ech_source(&b64).unwrap(),
            EchSource::RawConfigList(vec![0, 4, 1, 2, 3, 4])
        );
        assert!(parse_ech_source("not-valid").is_err());
    }

    #[tokio::test]
    async fn load_creates_default_and_recovers_corrupt_json() {
        let store = MemoryStorage::new();
        let (cfg, created) = Config::load_from(&store).await.unwrap();
        assert!(created);
        assert_eq!(cfg, Config::default());

        // Partial/corrupt JSON gets backed up and reset.
        store.write(CONFIG_FILE_NAME, b"{broken json").await.unwrap();
        let (cfg2, recovered) = Config::load_from(&store).await.unwrap();
        assert!(recovered);
        assert_eq!(cfg2, Config::default());
        assert_eq!(
            store
                .read(&format!("{CONFIG_FILE_NAME}.corrupt"))
                .await
                .unwrap()
                .as_deref(),
            Some(b"{broken json".as_slice())
        );
    }
}
