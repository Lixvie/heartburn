//! Typed error hierarchy for `heartburn-core`.

use std::io;
use std::time::Duration;
use thiserror::Error;

/// Top-level error type returned by `heartburn-core`.
#[derive(Debug, Error)]
pub enum HeartburnError {
    #[error("configuration error: {0}")]
    Config(#[from] ConfigError),

    #[error("storage error: {0}")]
    Storage(#[from] StorageError),

    #[error("dial error: {0}")]
    Dial(#[from] DialError),

    #[error("TLS error: {0}")]
    Tls(#[from] TlsError),

    #[error("DNS error: {0}")]
    Dns(#[from] DnsError),

    #[error("Firefox Accounts error: {0}")]
    Fxa(#[from] FxaError),

    #[error("Guardian API error: {0}")]
    Guardian(#[from] GuardianError),

    #[error("server list error: {0}")]
    ServerList(#[from] ServerListError),

    #[error("proxy error: {0}")]
    Proxy(#[from] ProxyError),

    #[error("controller is already running")]
    AlreadyRunning,

    #[error("controller is not running")]
    NotRunning,

    #[error("operation cancelled")]
    Cancelled,
}

/// Errors arising when loading, parsing, or validating configuration.
#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("invalid JSON in config: {0}")]
    Json(#[from] serde_json::Error),

    #[error("storage I/O failed: {0}")]
    Storage(#[from] StorageError),

    #[error("invalid duration string {0:?}")]
    InvalidDuration(String),

    #[error("{field}: {message}")]
    Validation {
        field: &'static str,
        message: String,
    },
}

/// Errors from the storage abstraction or filesystem persistence.
#[derive(Debug, Error)]
pub enum StorageError {
    #[error("storage key {0:?} is invalid")]
    InvalidKey(String),

    #[error("item {0:?} not found")]
    NotFound(String),

    #[error("I/O error on {path}: {source}")]
    Io {
        path: String,
        #[source]
        source: io::Error,
    },

    #[error("serialization error: {0}")]
    Serialization(String),
}

/// Errors from TCP/UDP socket creation, protection, or SOCKS5 upstream dialing.
#[derive(Debug, Error)]
pub enum DialError {
    #[error("invalid target address {0:?}: {1}")]
    InvalidAddress(String, String),

    #[error("socket protector hook failed: {0}")]
    Protect(#[source] io::Error),

    #[error("socket I/O failed: {0}")]
    Io(#[from] io::Error),

    #[error("DNS resolution failed: {0}")]
    Dns(#[from] DnsError),

    #[error("upstream SOCKS5 proxy error: {0}")]
    Socks5(String),

    #[error("connection timed out")]
    Timeout,

    #[error("no addresses available to dial {0}")]
    NoAddresses(String),
}

/// Errors from TLS handshake or ECH configuration/verification.
#[derive(Debug, Error)]
pub enum TlsError {
    #[error("invalid server name {0:?}")]
    InvalidServerName(String),

    #[error("invalid ECH config: {0}")]
    InvalidEchConfig(String),

    #[error("ECH was rejected by server")]
    EchRejected { retry_configs: Option<Vec<u8>> },

    #[error("certificate store error: {0}")]
    CertStore(String),

    #[error("TLS configuration error: {0}")]
    Config(String),

    #[error("TLS handshake or transport error: {0}")]
    Handshake(#[source] io::Error),

    #[error("TLS backend feature not enabled: {0}")]
    UnsupportedBackend(&'static str),
}

/// Errors from the bootstrap DNS/DoH/DoT/ECH resolver.
#[derive(Debug, Error)]
pub enum DnsError {
    #[error("invalid domain name {0:?}")]
    InvalidName(String),

    #[error("invalid DNS server entry {0:?}: {1}")]
    InvalidServer(String, String),

    #[error("invalid DNS wire message: {0}")]
    Wire(String),

    #[error("DNS query timed out")]
    Timeout,

    #[error("all DNS servers failed: {0}")]
    AllFailed(String),

    #[error("DNS transport I/O failed: {0}")]
    Io(#[from] io::Error),
}

/// Errors from Firefox Accounts (FxA) authentication and OAuth flows.
#[derive(Debug, Error)]
pub enum FxaError {
    #[error("invalid credentials or email")]
    InvalidInput(String),

    #[error("FxA API error (HTTP {status}, errno {errno}): {message}")]
    Api {
        status: u16,
        errno: u32,
        code: String,
        message: String,
    },

    #[error("sign-in verification required: {method}")]
    VerificationRequired { method: String },

    #[error("Fastly challenge blocked sign-in: {0}")]
    ChallengeBlocked(String),

    #[error("network/transport error: {0}")]
    Transport(String),

    #[error("cryptographic error: {0}")]
    Crypto(String),

    #[error("unexpected response: {0}")]
    Protocol(String),
}

/// Errors from Mozilla Guardian ProxyPass and quota endpoints.
#[derive(Debug, Error)]
pub enum GuardianError {
    #[error("Guardian HTTP {status}: {message}")]
    Http { status: u16, message: String },

    #[error("subscription required (no active Mozilla VPN entitlement)")]
    NoSubscription,

    #[error("unauthorized token")]
    Unauthorized,

    #[error("rate limited by Guardian (retry after {retry_after:?})")]
    RateLimited { retry_after: Option<Duration> },

    #[error("service unavailable in region (HTTP 451)")]
    RegionBlocked,

    #[error("invalid Guardian JWT or response: {0}")]
    Protocol(String),

    #[error("Guardian transport error: {0}")]
    Transport(String),
}

/// Errors from Mozilla Remote Settings / server list synchronization.
#[derive(Debug, Error)]
pub enum ServerListError {
    #[error("no eligible proxy servers matched {0}")]
    NoMatchingServers(String),

    #[error("JEXL filter error: {0}")]
    Filter(String),

    #[error("server list fetch failed: {0}")]
    Fetch(String),

    #[error("invalid server list JSON: {0}")]
    Json(#[from] serde_json::Error),
}

/// Errors from upstream sessions, failover, or local SOCKS5/HTTP inbound.
#[derive(Debug, Error)]
pub enum ProxyError {
    #[error("proxy transport error: {0}")]
    Transport(String),

    #[error("upstream HTTP status {status}: {message}")]
    UpstreamStatus { status: u16, message: String },

    #[error("target port {0} rejected by proxy policy")]
    PortRejected(u16),

    #[error("connection failed: {0}")]
    Io(#[from] io::Error),

    #[error("tunnel authentication failed")]
    AuthFailed,

    #[error("no accounts available")]
    NoAccounts,

    #[error("all accounts exhausted")]
    AllAccountsExhausted,

    #[error("failover cooldown active for server {0}")]
    ServerAvoided(String),

    #[error("invalid SOCKS5/HTTP request: {0}")]
    Protocol(String),
}

/// Result alias using [`HeartburnError`].
pub type Result<T> = std::result::Result<T, HeartburnError>;
