//! Pluggable TLS connector abstraction with `rustls` default backend and
//! optional Firefox 158 BoringSSL backend (`firefox-tls` feature).

use std::fmt;
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use rustls::client::EchConfig as RustlsEchConfig;
use rustls::internal::msgs::codec::Codec;
use rustls::pki_types::{EchConfigListBytes, ServerName};
use rustls::{ClientConfig, PeerIncompatible, RootCertStore};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::error::TlsError;
use crate::hpke_ring;

/// Embedded GlobalSign Root R46 and Root E46 CAs needed by Mozilla/Fastly on older stores.
const EXTRA_ROOTS_PEM: &str = include_str!("../assets/extra-roots.pem");

/// TLS fingerprint / ClientHello profile requested for an outbound connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TlsFingerprint {
    /// Standard `rustls` (`ring`) ClientHello.
    #[default]
    Default,
    /// Firefox 158 TLS fingerprint (full fidelity when built with `--features firefox-tls`,
    /// otherwise falls back cleanly to the `rustls` baseline).
    Firefox158,
}

/// Per-connection TLS handshake options.
#[derive(Debug, Clone, Default)]
pub struct TlsConfig {
    /// Server name placed into SNI and validated against the peer certificate.
    pub server_name: String,
    /// ALPN protocols in preference order (e.g., `vec![b"h2".to_vec(), b"http/1.1".to_vec()]`).
    pub alpn: Vec<Vec<u8>>,
    /// Raw RFC 9460/draft-ietf-tls-esni `ECHConfigList` bytes to enable TLS 1.3 ECH.
    pub ech_config_list: Option<Vec<u8>>,
    /// Force TLS 1.2 only (used for `chatgpt.com` Cloudflare edge TLS 1.2 relay fallback).
    pub tls12_only: bool,
    /// TLS fingerprint profile.
    pub fingerprint: TlsFingerprint,
}

/// Object-safe async stream trait for TLS transports.
pub trait DynStream: AsyncRead + AsyncWrite + Send + Unpin {}
impl<T: AsyncRead + AsyncWrite + Send + Unpin> DynStream for T {}

/// Boxed async stream passed into [`TlsConnector::connect`].
pub type BoxStream = Box<dyn DynStream>;

/// Boxed future returned by [`TlsConnector::connect`].
pub type TlsConnectFuture<'a> = Pin<Box<dyn Future<Output = Result<BoxedTlsStream, TlsError>> + Send + 'a>>;

/// Negotiated TLS stream carrying optional negotiated ALPN protocol bytes.
pub struct BoxedTlsStream {
    inner: BoxStream,
    alpn: Option<Vec<u8>>,
}

impl fmt::Debug for BoxedTlsStream {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BoxedTlsStream")
            .field("alpn", &self.alpn.as_deref().map(String::from_utf8_lossy))
            .finish()
    }
}

impl BoxedTlsStream {
    pub fn new(inner: BoxStream, alpn: Option<Vec<u8>>) -> Self {
        Self { inner, alpn }
    }

    /// Returns the ALPN protocol selected by the server during the handshake, if any.
    pub fn alpn_protocol(&self) -> Option<&[u8]> {
        self.alpn.as_deref()
    }

    /// Consumes the wrapper and yields the underlying boxed stream.
    pub fn into_inner(self) -> BoxStream {
        self.inner
    }
}

impl AsyncRead for BoxedTlsStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for BoxedTlsStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// Abstract TLS handshake connector allowing clean swapping between `rustls` and
/// optional Firefox-fingerprinted `boring2` backends.
pub trait TlsConnector: Send + Sync + fmt::Debug {
    /// Upgrades an arbitrary async transport stream to TLS using `config`.
    fn connect<'a>(&'a self, stream: BoxStream, config: &'a TlsConfig) -> TlsConnectFuture<'a>;
}

/// Builds the combined WebPKI + GlobalSign R46/E46 root certificate store.
pub fn build_root_store() -> Result<Arc<RootCertStore>, TlsError> {
    let mut roots = RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
    };
    let mut reader = io::BufReader::new(EXTRA_ROOTS_PEM.as_bytes());
    let extra_certs = rustls_pemfile::certs(&mut reader)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| TlsError::CertStore(format!("failed parsing extra-roots.pem: {e}")))?;
    let (added, _ignored) = roots.add_parsable_certificates(extra_certs);
    if added == 0 {
        return Err(TlsError::CertStore(
            "no certificates loaded from embedded extra-roots.pem".into(),
        ));
    }
    Ok(Arc::new(roots))
}

/// Default pure-Rust TLS backend powered by `rustls` (`ring` provider) + ECH.
#[derive(Clone, Debug)]
pub struct RustlsConnector {
    roots: Arc<RootCertStore>,
    provider: Arc<rustls::crypto::CryptoProvider>,
}

impl RustlsConnector {
    /// Creates a new `RustlsConnector` trusting Mozilla WebPKI roots + GlobalSign R46/E46.
    pub fn new() -> Result<Self, TlsError> {
        Ok(Self::with_roots(build_root_store()?))
    }

    /// Creates a `RustlsConnector` using a caller-supplied root certificate store.
    pub(crate) fn with_roots(roots: Arc<RootCertStore>) -> Self {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        Self { roots, provider }
    }

    /// Exposes the shared root store (e.g., for `quinn` HTTP/3 endpoint setup).
    pub fn roots(&self) -> &Arc<RootCertStore> {
        &self.roots
    }

    /// Builds a [`rustls::ClientConfig`] honoring ALPN, TLS 1.2 pinning, and ECH.
    pub fn build_client_config(&self, cfg: &TlsConfig) -> Result<ClientConfig, TlsError> {
        let builder = ClientConfig::builder_with_provider(Arc::clone(&self.provider));

        let mut client_cfg = if let Some(ref ech_raw) = cfg.ech_config_list {
            let ech_cfg = RustlsEchConfig::new(
                EchConfigListBytes::from(ech_raw.as_slice()),
                hpke_ring::ALL_SUPPORTED_SUITES,
            )
            .map_err(|e| TlsError::InvalidEchConfig(e.to_string()))?;
            builder
                .with_ech(ech_cfg.into())
                .map_err(|e| TlsError::Config(e.to_string()))?
                .with_root_certificates(Arc::clone(&self.roots))
                .with_no_client_auth()
        } else if cfg.tls12_only {
            builder
                .with_protocol_versions(&[&rustls::version::TLS12])
                .map_err(|e| TlsError::Config(e.to_string()))?
                .with_root_certificates(Arc::clone(&self.roots))
                .with_no_client_auth()
        } else {
            builder
                .with_safe_default_protocol_versions()
                .map_err(|e| TlsError::Config(e.to_string()))?
                .with_root_certificates(Arc::clone(&self.roots))
                .with_no_client_auth()
        };

        if !cfg.alpn.is_empty() {
            client_cfg.alpn_protocols = cfg.alpn.clone();
        }

        Ok(client_cfg)
    }
    #[inline(never)]
    fn build_arc_client_config(&self, cfg: &TlsConfig) -> Result<Arc<ClientConfig>, TlsError> {
        Ok(Arc::new(self.build_client_config(cfg)?))
    }
}

impl TlsConnector for RustlsConnector {
    fn connect<'a>(&'a self, stream: BoxStream, config: &'a TlsConfig) -> TlsConnectFuture<'a> {
        Box::pin(async move {
            let server_name = ServerName::try_from(config.server_name.clone())
                .map_err(|_| TlsError::InvalidServerName(config.server_name.clone()))?;
            let client_cfg = self.build_arc_client_config(config)?;
            let connector = tokio_rustls::TlsConnector::from(client_cfg);

            match Box::pin(connector.connect(server_name, stream)).await {
                Ok(tls_stream) => {
                    let (_, conn) = tls_stream.get_ref();
                    let alpn = conn.alpn_protocol().map(|p| p.to_vec());
                    Ok(BoxedTlsStream::new(Box::new(tls_stream), alpn))
                }
                Err(io_err) => Err(map_rustls_io_error(io_err)),
            }
        })
    }
}

fn map_rustls_io_error(err: io::Error) -> TlsError {
    if let Some(rustls_err) = err.get_ref().and_then(|e| e.downcast_ref::<rustls::Error>())
        && let rustls::Error::PeerIncompatible(
            PeerIncompatible::ServerRejectedEncryptedClientHello(retry),
        ) = rustls_err
    {
        let retry_configs = retry.as_ref().map(|configs| {
            let mut inner = Vec::new();
            for cfg in configs {
                cfg.encode(&mut inner);
            }
            let mut list = Vec::with_capacity(2 + inner.len());
            list.extend_from_slice(&(inner.len() as u16).to_be_bytes());
            list.extend_from_slice(&inner);
            list
        });
        return TlsError::EchRejected { retry_configs };
    }
    TlsError::Handshake(err)
}

/// Human-readable name of the active TLS backend used for `TlsFingerprint::Firefox158`.
pub const fn tls_backend_name() -> &'static str {
    #[cfg(feature = "firefox-tls")]
    {
        "boring2 firefox-tls"
    }
    #[cfg(not(feature = "firefox-tls"))]
    {
        "rustls"
    }
}

/// Selects [`FirefoxBoringConnector`] when compiled with `--features firefox-tls` and
/// requested by [`TlsFingerprint::Firefox158`], otherwise delegating to [`RustlsConnector`].
#[derive(Debug)]
pub struct AdaptiveTlsConnector {
    rustls: RustlsConnector,
    #[cfg(feature = "firefox-tls")]
    firefox: firefox_boring::FirefoxBoringConnector,
}

impl AdaptiveTlsConnector {
    /// Creates the default adaptive connector.
    pub fn new() -> Result<Self, TlsError> {
        let rustls = RustlsConnector::new()?;
        #[cfg(feature = "firefox-tls")]
        let firefox =
            firefox_boring::FirefoxBoringConnector::with_roots(Arc::clone(rustls.roots()))?;
        tracing::debug!(backend = tls_backend_name(), "initialized adaptive TLS connector");
        Ok(Self {
            rustls,
            #[cfg(feature = "firefox-tls")]
            firefox,
        })
    }

    /// Accesses the underlying `RustlsConnector` (needed for QUIC / H3 setup).
    pub fn rustls(&self) -> &RustlsConnector {
        &self.rustls
    }

    #[cfg(all(test, feature = "firefox-tls"))]
    pub(crate) fn with_roots(roots: Arc<RootCertStore>) -> Result<Self, TlsError> {
        let rustls = RustlsConnector::with_roots(Arc::clone(&roots));
        let firefox = firefox_boring::FirefoxBoringConnector::with_roots(roots)?;
        Ok(Self { rustls, firefox })
    }
}

impl TlsConnector for AdaptiveTlsConnector {
    fn connect<'a>(&'a self, stream: BoxStream, config: &'a TlsConfig) -> TlsConnectFuture<'a> {
        #[cfg(feature = "firefox-tls")]
        {
            // Active ECH (`ech_config_list.is_some()`) falls back cleanly to `RustlsConnector`:
            // `boring-sys2`'s Firefox cipher-order patch omits TLS 1.3 cipher suites from
            // `ssl_client_hello_inner`, which causes ECH-capable servers to reject BoringSSL's
            // encrypted inner ClientHello. ECH GREASE (`ech_config_list.is_none()`) stays on BoringSSL.
            if matches!(config.fingerprint, TlsFingerprint::Firefox158)
                && config.ech_config_list.is_none()
            {
                return self.firefox.connect(stream, config);
            }
        }
        self.rustls.connect(stream, config)
    }
}

#[cfg(feature = "firefox-tls")]
pub mod firefox_boring {
    //! Firefox 158 TLS fingerprinting backend built on `boring2` + `tokio-boring2`.

    use super::*;
    use boring2::ssl::{
        CertificateCompressionAlgorithm, CertificateCompressor, ConnectConfiguration, SslAlert,
        SslConnector, SslMethod, SslRef, SslVerifyError, SslVerifyMode, SslVersion,
    };
    use rustls::CertificateError;
    use rustls::client::WebPkiServerVerifier;
    use rustls::client::danger::ServerCertVerifier;
    use rustls::pki_types::{CertificateDer, UnixTime};

    // Firefox 158 cipher suite preference list (`firefoxtls.go`).
    // Note: `boring-sys2` patches BoringSSL's `ssl_write_client_cipher_list` so TLS 1.3
    // cipher suites come directly from `set_cipher_list` rather than being auto-prepended.
    const FIREFOX_CIPHER_LIST: &str = concat!(
        "TLS_AES_128_GCM_SHA256:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_256_GCM_SHA384:",
        "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:",
        "ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:",
        "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:",
        "ECDHE-RSA-AES128-SHA:ECDHE-RSA-AES256-SHA:",
        "AES128-GCM-SHA256:AES256-GCM-SHA384:",
        "AES128-SHA:AES256-SHA",
    );

    const FIREFOX_CURVES_LIST: &str = "X25519MLKEM768:X25519:P-256:P-384:P-521";

    const FIREFOX_SIGALGS_LIST: &str = concat!(
        "ecdsa_secp256r1_sha256:ecdsa_secp384r1_sha384:ecdsa_secp521r1_sha512:",
        "rsa_pss_rsae_sha256:rsa_pss_rsae_sha384:rsa_pss_rsae_sha512:",
        "rsa_pkcs1_sha256:rsa_pkcs1_sha384:rsa_pkcs1_sha512:",
        "ecdsa_sha1:rsa_pkcs1_sha1",
    );

    const FIREFOX_DELEGATED_CREDENTIALS_SIGALGS: &str =
        "ecdsa_secp256r1_sha256:ecdsa_secp384r1_sha384:ecdsa_secp521r1_sha512:ecdsa_sha1";

    const FIREFOX_RECORD_SIZE_LIMIT: u16 = 0x4001;

    pub(crate) struct ZlibCertDecompressor;

    impl CertificateCompressor for ZlibCertDecompressor {
        const ALGORITHM: CertificateCompressionAlgorithm = CertificateCompressionAlgorithm::ZLIB;
        const CAN_COMPRESS: bool = false;
        const CAN_DECOMPRESS: bool = true;

        fn decompress<W>(&self, input: &[u8], output: &mut W) -> io::Result<()>
        where
            W: io::Write,
        {
            let mut decoder = flate2::read::ZlibDecoder::new(input);
            io::copy(&mut decoder, output)?;
            Ok(())
        }
    }

    pub(crate) struct BrotliCertDecompressor;

    impl CertificateCompressor for BrotliCertDecompressor {
        const ALGORITHM: CertificateCompressionAlgorithm = CertificateCompressionAlgorithm::BROTLI;
        const CAN_COMPRESS: bool = false;
        const CAN_DECOMPRESS: bool = true;

        fn decompress<W>(&self, input: &[u8], output: &mut W) -> io::Result<()>
        where
            W: io::Write,
        {
            let mut decoder = brotli_decompressor::Decompressor::new(input, 4096);
            io::copy(&mut decoder, output)?;
            Ok(())
        }
    }

    /// BoringSSL connector mimicking desktop Firefox 158's cipher suites, curves
    /// (including `X25519MLKEM768`), key shares, signature algorithms, OCSP/SCT,
    /// delegated credentials, record size limit, cert decompression, ALPN, and ECH.
    #[derive(Clone)]
    pub struct FirefoxBoringConnector {
        tls13: Arc<SslConnector>,
        tls12: Arc<SslConnector>,
        verifier: Arc<WebPkiServerVerifier>,
    }

    impl fmt::Debug for FirefoxBoringConnector {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.debug_struct("FirefoxBoringConnector").finish_non_exhaustive()
        }
    }

    impl FirefoxBoringConnector {
        /// Creates a `FirefoxBoringConnector` trusting Mozilla WebPKI roots + GlobalSign R46/E46.
        pub fn new() -> Result<Self, TlsError> {
            Self::with_roots(build_root_store()?)
        }

        /// Creates a `FirefoxBoringConnector` verifying peer certificates via `roots`.
        pub fn with_roots(roots: Arc<RootCertStore>) -> Result<Self, TlsError> {
            let provider = Arc::new(rustls::crypto::ring::default_provider());
            let verifier = WebPkiServerVerifier::builder_with_provider(roots, provider)
                .build()
                .map_err(|e| {
                    TlsError::CertStore(format!("failed building WebPKI verifier: {e}"))
                })?;

            let tls13 = Arc::new(Self::build_base_connector(false)?);
            let tls12 = Arc::new(Self::build_base_connector(true)?);
            Ok(Self {
                tls13,
                tls12,
                verifier,
            })
        }

        fn build_base_connector(tls12_only: bool) -> Result<SslConnector, TlsError> {
            let mut builder = SslConnector::builder(SslMethod::tls_client())
                .map_err(|e| TlsError::Config(e.to_string()))?;

            builder
                .set_min_proto_version(Some(SslVersion::TLS1_2))
                .map_err(|e| TlsError::Config(e.to_string()))?;
            builder
                .set_max_proto_version(Some(if tls12_only {
                    SslVersion::TLS1_2
                } else {
                    SslVersion::TLS1_3
                }))
                .map_err(|e| TlsError::Config(e.to_string()))?;

            builder
                .set_cipher_list(FIREFOX_CIPHER_LIST)
                .map_err(|e| TlsError::Config(e.to_string()))?;
            builder.set_aes_hw_override(true);

            builder
                .set_curves_list(FIREFOX_CURVES_LIST)
                .map_err(|e| TlsError::Config(e.to_string()))?;
            builder.set_key_shares_limit(3);

            builder
                .set_sigalgs_list(FIREFOX_SIGALGS_LIST)
                .map_err(|e| TlsError::Config(e.to_string()))?;
            builder
                .set_delegated_credentials(FIREFOX_DELEGATED_CREDENTIALS_SIGALGS)
                .map_err(|e| TlsError::Config(e.to_string()))?;
            builder.set_record_size_limit(FIREFOX_RECORD_SIZE_LIMIT);
            builder.enable_ocsp_stapling();
            builder.enable_signed_cert_timestamps();

            // Firefox keeps deterministic extension order and does not emit Chrome cipher/group GREASE.
            builder.set_permute_extensions(false);
            builder.set_grease_enabled(false);

            builder
                .add_certificate_compression_algorithm(ZlibCertDecompressor)
                .map_err(|e| TlsError::Config(e.to_string()))?;
            builder
                .add_certificate_compression_algorithm(BrotliCertDecompressor)
                .map_err(|e| TlsError::Config(e.to_string()))?;

            Ok(builder.build())
        }

        /// Configures a per-connection `ConnectConfiguration` with ALPN, ECH / ECH GREASE,
        /// and custom WebPKI certificate + ECH name-override verification.
        pub(crate) fn configure_ssl(&self, config: &TlsConfig) -> Result<ConnectConfiguration, TlsError> {
            ServerName::try_from(config.server_name.clone())
                .map_err(|_| TlsError::InvalidServerName(config.server_name.clone()))?;

            let base = if config.tls12_only {
                &self.tls12
            } else {
                &self.tls13
            };
            let mut ssl_cfg = base
                .configure()
                .map_err(|e| TlsError::Config(e.to_string()))?;
            // Hostname and chain validation are handled uniformly by WebPkiServerVerifier below.
            ssl_cfg.set_verify_hostname(false);

            if !config.alpn.is_empty() {
                let mut wire = Vec::new();
                for proto in &config.alpn {
                    if proto.len() <= u8::MAX as usize {
                        wire.push(proto.len() as u8);
                        wire.extend_from_slice(proto);
                    }
                }
                if !wire.is_empty() {
                    ssl_cfg
                        .set_alpn_protos(&wire)
                        .map_err(|e| TlsError::Config(e.to_string()))?;
                }
            }

            if !config.tls12_only {
                if let Some(ref ech_raw) = config.ech_config_list {
                    ssl_cfg
                        .set_ech_config_list(ech_raw)
                        .map_err(|e| TlsError::InvalidEchConfig(e.to_string()))?;
                } else {
                    ssl_cfg.set_enable_ech_grease(true);
                }
            }

            let verifier = Arc::clone(&self.verifier);
            let server_name = config.server_name.clone();
            ssl_cfg.set_custom_verify_callback(SslVerifyMode::PEER, move |ssl| {
                verify_peer_chain(verifier.as_ref(), &server_name, ssl)
            });

            Ok(ssl_cfg)
        }
    }

    fn verify_peer_chain(
        verifier: &dyn ServerCertVerifier,
        server_name: &str,
        ssl: &mut SslRef,
    ) -> Result<(), SslVerifyError> {
        let verify_host = ssl
            .get_ech_name_override()
            .and_then(|bytes| std::str::from_utf8(bytes).ok())
            .filter(|name| !name.is_empty())
            .unwrap_or(server_name);
        let Ok(sni) = ServerName::try_from(verify_host.to_owned()) else {
            return Err(SslVerifyError::Invalid(SslAlert::UNRECOGNIZED_NAME));
        };

        let Some(chain) = ssl.peer_cert_chain() else {
            return Err(SslVerifyError::Invalid(SslAlert::NO_CERTIFICATE));
        };
        let mut der_chain = Vec::with_capacity(chain.len());
        for cert in chain {
            let Ok(der) = cert.to_der() else {
                return Err(SslVerifyError::Invalid(SslAlert::DECODE_ERROR));
            };
            der_chain.push(CertificateDer::from(der));
        }
        let Some((end_entity, intermediates)) = der_chain.split_first() else {
            return Err(SslVerifyError::Invalid(SslAlert::NO_CERTIFICATE));
        };

        let ocsp = ssl.ocsp_status().unwrap_or(&[]);
        verifier
            .verify_server_cert(end_entity, intermediates, &sni, ocsp, UnixTime::now())
            .map(|_| ())
            .map_err(map_rustls_verify_error_to_alert)
    }

    fn map_rustls_verify_error_to_alert(err: rustls::Error) -> SslVerifyError {
        let alert = match err {
            rustls::Error::InvalidCertificate(cert_err) => match cert_err {
                CertificateError::Expired
                | CertificateError::ExpiredContext { .. }
                | CertificateError::NotValidYet
                | CertificateError::NotValidYetContext { .. } => SslAlert::CERTIFICATE_EXPIRED,
                CertificateError::Revoked => SslAlert::CERTIFICATE_REVOKED,
                CertificateError::UnknownIssuer => SslAlert::UNKNOWN_CA,
                _ => SslAlert::BAD_CERTIFICATE,
            },
            _ => SslAlert::BAD_CERTIFICATE,
        };
        SslVerifyError::Invalid(alert)
    }

    fn is_ech_rejected_error(ssl_err: &boring2::ssl::Error) -> bool {
        ssl_err.ssl_error().is_some_and(|stack| {
            stack
                .errors()
                .iter()
                .any(|entry| entry.reason() == Some("ECH_REJECTED"))
        })
    }

    fn map_boring_handshake_error<S: fmt::Debug>(
        err: tokio_boring2::HandshakeError<S>,
    ) -> TlsError {
        let retry_configs = err
            .ssl()
            .and_then(|ssl| ssl.get_ech_retry_configs())
            .map(|bytes| bytes.to_vec());
        let mut cur: Option<&(dyn std::error::Error + 'static)> = std::error::Error::source(&err);
        while let Some(source) = cur {
            if let Some(ssl_err) = source.downcast_ref::<boring2::ssl::Error>()
                && is_ech_rejected_error(ssl_err)
            {
                return TlsError::EchRejected { retry_configs };
            }
            cur = source.source();
        }
        TlsError::Handshake(io::Error::other(err.to_string()))
    }

    struct DebugStream(BoxStream);

    impl fmt::Debug for DebugStream {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("BoxStream")
        }
    }

    impl AsyncRead for DebugStream {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            Pin::new(&mut self.0).poll_read(cx, buf)
        }
    }

    impl AsyncWrite for DebugStream {
        fn poll_write(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            Pin::new(&mut self.0).poll_write(cx, buf)
        }

        fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.0).poll_flush(cx)
        }

        fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.0).poll_shutdown(cx)
        }
    }

    impl TlsConnector for FirefoxBoringConnector {
        fn connect<'a>(&'a self, stream: BoxStream, config: &'a TlsConfig) -> TlsConnectFuture<'a> {
            Box::pin(async move {
                let ssl_cfg = self.configure_ssl(config)?;
                let tls_stream = Box::pin(tokio_boring2::connect(
                    ssl_cfg,
                    &config.server_name,
                    DebugStream(stream),
                ))
                .await
                .map_err(map_boring_handshake_error)?;
                let alpn = tls_stream
                    .ssl()
                    .selected_alpn_protocol()
                    .map(|p| p.to_vec());
                Ok(BoxedTlsStream::new(Box::new(tls_stream), alpn))
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_root_store_with_globalsign_r46_and_e46() {
        let base_count = webpki_roots::TLS_SERVER_ROOTS.len();
        let store = build_root_store().unwrap();
        assert!(store.len() >= base_count + 2);
    }

    #[test]
    fn builds_rustls_client_config_variants() {
        let conn = RustlsConnector::new().unwrap();
        let default_cfg = TlsConfig {
            server_name: "vpn.mozilla.org".into(),
            alpn: vec![b"h2".to_vec(), b"http/1.1".to_vec()],
            ..Default::default()
        };
        let built = conn.build_client_config(&default_cfg).unwrap();
        assert_eq!(built.alpn_protocols, vec![b"h2".to_vec(), b"http/1.1".to_vec()]);

        let tls12_cfg = TlsConfig {
            server_name: "chatgpt.com".into(),
            tls12_only: true,
            ..Default::default()
        };
        conn.build_client_config(&tls12_cfg).unwrap();
    }

    #[test]
    fn reports_expected_tls_backend_name() {
        #[cfg(feature = "firefox-tls")]
        assert_eq!(tls_backend_name(), "boring2 firefox-tls");
        #[cfg(not(feature = "firefox-tls"))]
        assert_eq!(tls_backend_name(), "rustls");
    }

    #[cfg(feature = "firefox-tls")]
    mod firefox_tests {
        use super::firefox_boring::FirefoxBoringConnector;
        use super::*;
        use std::io::Write;
        use std::sync::{Arc, Mutex};

        use boring2::asn1::Asn1Time;
        use boring2::bn::{BigNum, MsbOption};
        use boring2::hash::MessageDigest;
        use boring2::pkey::{PKey, Private};
        use boring2::rsa::Rsa;
        use boring2::ssl::{
            AlpnError, CertificateCompressionAlgorithm, CertificateCompressor, ExtensionType,
            NameType, SslAcceptor, SslMethod, SslOptions, select_next_proto,
        };
        use boring2::x509::extension::{
            AuthorityKeyIdentifier, BasicConstraints, KeyUsage, SubjectAlternativeName,
            SubjectKeyIdentifier,
        };
        use boring2::x509::{X509, X509NameBuilder, X509Ref};
        use rustls::pki_types::CertificateDer;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::{TcpListener, TcpStream};

        struct ZlibTestServerCompressor;

        impl CertificateCompressor for ZlibTestServerCompressor {
            const ALGORITHM: CertificateCompressionAlgorithm = CertificateCompressionAlgorithm::ZLIB;
            const CAN_COMPRESS: bool = true;
            const CAN_DECOMPRESS: bool = false;

            fn compress<W>(&self, input: &[u8], output: &mut W) -> io::Result<()>
            where
                W: io::Write,
            {
                let mut encoder =
                    flate2::write::ZlibEncoder::new(output, flate2::Compression::fast());
                encoder.write_all(input)?;
                encoder.finish()?;
                Ok(())
            }
        }

        fn make_ca_and_leaf(
            sans: &[&str],
        ) -> (X509, PKey<Private>, X509, PKey<Private>, Arc<RootCertStore>) {
            let ca_rsa = Rsa::generate(2048).unwrap();
            let ca_key = PKey::from_rsa(ca_rsa).unwrap();
            let mut ca_name = X509NameBuilder::new().unwrap();
            ca_name.append_entry_by_text("CN", "Heartburn Test CA").unwrap();
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
            let ski = SubjectKeyIdentifier::new()
                .build(&ca_builder.x509v3_context(None, None))
                .unwrap();
            ca_builder.append_extension(ski).unwrap();
            ca_builder.sign(&ca_key, MessageDigest::sha256()).unwrap();
            let ca_cert = ca_builder.build();

            let leaf_rsa = Rsa::generate(2048).unwrap();
            let leaf_key = PKey::from_rsa(leaf_rsa).unwrap();
            let mut leaf_name = X509NameBuilder::new().unwrap();
            leaf_name
                .append_entry_by_text("CN", sans.first().copied().unwrap_or("localhost"))
                .unwrap();
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

            let mut san_builder = SubjectAlternativeName::new();
            for dns in sans {
                san_builder.dns(dns);
            }
            let san = san_builder
                .build(&leaf_builder.x509v3_context(ctx_ref, None))
                .unwrap();
            leaf_builder.append_extension(san).unwrap();
            leaf_builder.sign(&ca_key, MessageDigest::sha256()).unwrap();
            let leaf_cert = leaf_builder.build();

            let mut store = RootCertStore::empty();
            let ca_der = CertificateDer::from(ca_cert.to_der().unwrap());
            let (added, _) = store.add_parsable_certificates([ca_der]);
            assert_eq!(added, 1);

            (ca_cert, ca_key, leaf_cert, leaf_key, Arc::new(store))
        }

        fn parse_u16_list(bytes: &[u8]) -> Vec<u16> {
            bytes
                .as_chunks::<2>()
                .0
                .iter()
                .copied()
                .map(u16::from_be_bytes)
                .collect()
        }

        /// Parses extension IDs in wire order from a ClientHello payload (`ClientHello::as_bytes()`).
        fn parse_client_hello_extension_ids(raw: &[u8]) -> Vec<u16> {
            // Legacy version (2) + random (32)
            let mut pos = 34;
            let sid_len = raw[pos] as usize;
            pos += 1 + sid_len;
            let cs_len = u16::from_be_bytes([raw[pos], raw[pos + 1]]) as usize;
            pos += 2 + cs_len;
            let comp_len = raw[pos] as usize;
            pos += 1 + comp_len;
            let ext_total = u16::from_be_bytes([raw[pos], raw[pos + 1]]) as usize;
            pos += 2;
            let end = pos + ext_total;
            let mut ids = Vec::new();
            while pos + 4 <= end {
                let id = u16::from_be_bytes([raw[pos], raw[pos + 1]]);
                let len = u16::from_be_bytes([raw[pos + 2], raw[pos + 3]]) as usize;
                ids.push(id);
                pos += 4 + len;
            }
            ids
        }

        #[derive(Debug, Default, Clone)]
        struct CapturedHello {
            cipher_ids: Vec<u16>,
            extension_ids: Vec<u16>,
            groups: Vec<u16>,
            key_share_groups: Vec<u16>,
            sigalgs: Vec<u16>,
            record_size_limit: Option<u16>,
            cert_comp_algs: Vec<u16>,
            has_delegated_cred: bool,
            has_ocsp_status_req: bool,
            has_sct: bool,
            has_ech: bool,
            outer_sni: Option<String>,
        }

        fn build_test_acceptor(
            leaf: &X509,
            key: &PKey<Private>,
            tls12_only: bool,
            compress_zlib: bool,
            captured: Option<Arc<Mutex<Vec<CapturedHello>>>>,
        ) -> SslAcceptor {
            let mut acceptor = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls()).unwrap();
            acceptor.set_certificate(leaf).unwrap();
            acceptor.set_private_key(key).unwrap();
            acceptor.check_private_key().unwrap();
            if tls12_only {
                acceptor.set_options(SslOptions::NO_TLSV1_3);
            }
            if compress_zlib {
                acceptor
                    .add_certificate_compression_algorithm(ZlibTestServerCompressor)
                    .unwrap();
            }
            acceptor.set_alpn_select_callback(|_, client_protos| {
                select_next_proto(b"\x02h2\x08http/1.1", client_protos).ok_or(AlpnError::NOACK)
            });

            if let Some(sink) = captured {
                acceptor.set_select_certificate_callback(move |ch| {
                    let mut info = CapturedHello {
                        cipher_ids: parse_u16_list(ch.ciphers()),
                        extension_ids: parse_client_hello_extension_ids(ch.as_bytes()),
                        has_delegated_cred: ch
                            .get_extension(ExtensionType::DELEGATED_CREDENTIAL)
                            .is_some(),
                        has_ocsp_status_req: ch
                            .get_extension(ExtensionType::STATUS_REQUEST)
                            .is_some(),
                        has_sct: ch
                            .get_extension(ExtensionType::CERTIFICATE_TIMESTAMP)
                            .is_some(),
                        has_ech: ch
                            .get_extension(ExtensionType::ENCRYPTED_CLIENT_HELLO)
                            .is_some(),
                        outer_sni: ch.servername(NameType::HOST_NAME).map(ToOwned::to_owned),
                        ..Default::default()
                    };
                    if let Some(ext) = ch.get_extension(ExtensionType::SUPPORTED_GROUPS)
                        && ext.len() >= 2
                    {
                        let len = u16::from_be_bytes([ext[0], ext[1]]) as usize;
                        info.groups = parse_u16_list(&ext[2..2 + len.min(ext.len() - 2)]);
                    }
                    if let Some(ext) = ch.get_extension(ExtensionType::KEY_SHARE)
                        && ext.len() >= 2
                    {
                        let mut p = 2;
                        let end = (2 + u16::from_be_bytes([ext[0], ext[1]]) as usize).min(ext.len());
                        while p + 4 <= end {
                            let g = u16::from_be_bytes([ext[p], ext[p + 1]]);
                            let klen = u16::from_be_bytes([ext[p + 2], ext[p + 3]]) as usize;
                            info.key_share_groups.push(g);
                            p += 4 + klen;
                        }
                    }
                    if let Some(ext) = ch.get_extension(ExtensionType::SIGNATURE_ALGORITHMS)
                        && ext.len() >= 2
                    {
                        let len = u16::from_be_bytes([ext[0], ext[1]]) as usize;
                        info.sigalgs = parse_u16_list(&ext[2..2 + len.min(ext.len() - 2)]);
                    }
                    if let Some(ext) = ch.get_extension(ExtensionType::RECORD_SIZE_LIMIT)
                        && ext.len() == 2
                    {
                        info.record_size_limit = Some(u16::from_be_bytes([ext[0], ext[1]]));
                    }
                    if let Some(ext) = ch.get_extension(ExtensionType::CERT_COMPRESSION)
                        && !ext.is_empty()
                    {
                        let len = (ext[0] as usize).min(ext.len() - 1);
                        info.cert_comp_algs = parse_u16_list(&ext[1..1 + len]);
                    }
                    sink.lock().unwrap().push(info);
                    Ok(())
                });
            }

            acceptor.build()
        }

        #[test]
        fn configures_firefox_profile_and_rejects_bad_inputs() {
            let conn = FirefoxBoringConnector::new().unwrap();

            let cfg = TlsConfig {
                server_name: "vpn.mozilla.org".into(),
                alpn: vec![b"h2".to_vec(), b"http/1.1".to_vec()],
                fingerprint: TlsFingerprint::Firefox158,
                ..Default::default()
            };
            let ssl_cfg = conn.configure_ssl(&cfg).unwrap();
            let ssl = ssl_cfg.into_ssl("vpn.mozilla.org").unwrap();
            assert!(!ssl.ciphers().is_empty());

            let tls12_cfg = TlsConfig {
                server_name: "chatgpt.com".into(),
                tls12_only: true,
                fingerprint: TlsFingerprint::Firefox158,
                ..Default::default()
            };
            conn.configure_ssl(&tls12_cfg).unwrap();

            let bad_sni = TlsConfig {
                server_name: String::new(),
                fingerprint: TlsFingerprint::Firefox158,
                ..Default::default()
            };
            assert!(matches!(
                conn.configure_ssl(&bad_sni),
                Err(TlsError::InvalidServerName(_))
            ));

            let bad_ech = TlsConfig {
                server_name: "vpn.mozilla.org".into(),
                ech_config_list: Some(vec![1, 2, 3]),
                fingerprint: TlsFingerprint::Firefox158,
                ..Default::default()
            };
            assert!(matches!(
                conn.configure_ssl(&bad_ech),
                Err(TlsError::InvalidEchConfig(_))
            ));
        }

        #[tokio::test]
        async fn wire_client_hello_matches_firefox158_and_completes_compressed_handshake() {
            let (_ca_cert, _ca_key, leaf_cert, leaf_key, roots) =
                make_ca_and_leaf(&["firefox-test.example"]);
            let captured = Arc::new(Mutex::new(Vec::new()));
            let acceptor = Arc::new(build_test_acceptor(
                &leaf_cert,
                &leaf_key,
                false,
                true,
                Some(Arc::clone(&captured)),
            ));

            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();

            let server_task = tokio::spawn({
                let acceptor = Arc::clone(&acceptor);
                async move {
                    for _ in 0..2 {
                        let (tcp, _) = listener.accept().await.unwrap();
                        let mut tls = tokio_boring2::accept(&acceptor, tcp).await.unwrap();
                        let mut buf = [0u8; 4];
                        tls.read_exact(&mut buf).await.unwrap();
                        assert_eq!(&buf, b"ping");
                        tls.write_all(b"pong").await.unwrap();
                        tls.shutdown().await.unwrap();
                    }
                }
            });

            let client = FirefoxBoringConnector::with_roots(Arc::clone(&roots)).unwrap();
            let cfg = TlsConfig {
                server_name: "firefox-test.example".into(),
                alpn: vec![b"h2".to_vec(), b"http/1.1".to_vec()],
                fingerprint: TlsFingerprint::Firefox158,
                ..Default::default()
            };

            for _ in 0..2 {
                let tcp = TcpStream::connect(addr).await.unwrap();
                let mut tls = client.connect(Box::new(tcp), &cfg).await.unwrap();
                assert_eq!(tls.alpn_protocol(), Some(b"h2".as_slice()));
                tls.write_all(b"ping").await.unwrap();
                let mut reply = [0u8; 4];
                tls.read_exact(&mut reply).await.unwrap();
                assert_eq!(&reply, b"pong");
            }
            server_task.await.unwrap();

            let hellos = captured.lock().unwrap();
            assert_eq!(hellos.len(), 2);
            let ch = &hellos[0];

            // Exact Firefox 158 cipher suite list in preference order (no GREASE cipher IDs).
            assert_eq!(
                ch.cipher_ids,
                vec![
                    0x1301, 0x1303, 0x1302, // TLS 1.3 AES-128-GCM, ChaCha20, AES-256-GCM
                    0xc02b, 0xc02f, 0xcca9, 0xcca8, 0xc02c, 0xc030, // ECDHE GCM / ChaCha20
                    0xc013, 0xc014, 0x009c, 0x009d, 0x002f, 0x0035, // ECDHE-RSA CBC + RSA
                ]
            );
            assert_eq!(
                ch.groups,
                vec![0x11ec, 0x001d, 0x0017, 0x0018, 0x0019] // X25519MLKEM768, X25519, P-256, P-384, P-521
            );
            assert_eq!(ch.key_share_groups, vec![0x11ec, 0x001d, 0x0017]);
            assert_eq!(
                ch.sigalgs,
                vec![
                    0x0403, 0x0503, 0x0603, // ecdsa P-256/P-384/P-521
                    0x0804, 0x0805, 0x0806, // rsa_pss_rsae 256/384/512
                    0x0401, 0x0501, 0x0601, // rsa_pkcs1 256/384/512
                    0x0203, 0x0201, // ecdsa_sha1, rsa_pkcs1_sha1
                ]
            );
            assert_eq!(ch.record_size_limit, Some(0x4001));
            assert_eq!(ch.cert_comp_algs, vec![1, 2]); // Zlib, Brotli
            assert!(ch.has_delegated_cred);
            assert!(ch.has_ocsp_status_req);
            assert!(ch.has_sct);
            assert!(ch.has_ech); // ECH GREASE active on non-TLS1.2 connections without explicit ECH

            // Extension order stays deterministic across connections.
            assert_eq!(hellos[0].extension_ids, hellos[1].extension_ids);
        }

        #[tokio::test]
        async fn tls12_and_trust_store_enforcement_and_adaptive_dispatch() {
            let (_ca_cert, _ca_key, leaf_cert, leaf_key, roots) =
                make_ca_and_leaf(&["tls12-test.example"]);
            let acceptor = Arc::new(build_test_acceptor(
                &leaf_cert,
                &leaf_key,
                true,
                false,
                None,
            ));

            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();

            let server_task = tokio::spawn({
                let acceptor = Arc::clone(&acceptor);
                async move {
                    // 1. Valid TLS 1.2 + Firefox158
                    // 2. Wrong hostname (client rejects server cert)
                    // 3. Default AdaptiveTlsConnector without test root (client rejects untrusted CA)
                    // 4. Valid AdaptiveTlsConnector with Default fingerprint -> Rustls works with same roots
                    for i in 0..3 {
                        let (tcp, _) = listener.accept().await.unwrap();
                        let res = tokio_boring2::accept(&acceptor, tcp).await;
                        if i == 0 {
                            let mut tls = res.unwrap();
                            assert_eq!(tls.ssl().version_str(), "TLSv1.2");
                            let mut buf = [0u8; 2];
                            tls.read_exact(&mut buf).await.unwrap();
                            tls.write_all(b"ok").await.unwrap();
                            tls.shutdown().await.unwrap();
                        } else {
                            assert!(res.is_err());
                        }
                    }
                }
            });

            let client = FirefoxBoringConnector::with_roots(Arc::clone(&roots)).unwrap();
            let cfg = TlsConfig {
                server_name: "tls12-test.example".into(),
                alpn: vec![b"http/1.1".to_vec()],
                tls12_only: true,
                fingerprint: TlsFingerprint::Firefox158,
                ..Default::default()
            };
            let tcp1 = TcpStream::connect(addr).await.unwrap();
            let mut tls1 = client.connect(Box::new(tcp1), &cfg).await.unwrap();
            assert_eq!(tls1.alpn_protocol(), Some(b"http/1.1".as_slice()));
            tls1.write_all(b"hi").await.unwrap();
            let mut reply = [0u8; 2];
            tls1.read_exact(&mut reply).await.unwrap();
            assert_eq!(&reply, b"ok");

            let wrong_host_cfg = TlsConfig {
                server_name: "wrong-host.example".into(),
                tls12_only: true,
                fingerprint: TlsFingerprint::Firefox158,
                ..Default::default()
            };
            let tcp2 = TcpStream::connect(addr).await.unwrap();
            assert!(matches!(
                client.connect(Box::new(tcp2), &wrong_host_cfg).await,
                Err(TlsError::Handshake(_))
            ));

            // Default production root store must reject our synthetic test CA.
            let adaptive = AdaptiveTlsConnector::new().unwrap();
            let tcp3 = TcpStream::connect(addr).await.unwrap();
            assert!(matches!(
                adaptive.connect(Box::new(tcp3), &cfg).await,
                Err(TlsError::Handshake(_))
            ));

            server_task.await.unwrap();
        }

        #[tokio::test]
        async fn ech_uses_public_outer_sni_validates_ech_name_override_and_maps_rejection() {
            const ECH_CONFIG_1_LIST: &[u8] = &[
                0x00, 0x3e, 0xfe, 0x0d, 0x00, 0x3a, 0x00, 0x00, 0x20, 0x00, 0x20, 0xbb, 0x2f, 0x29,
                0xe3, 0xe3, 0x05, 0x7e, 0x04, 0x19, 0xd5, 0x2f, 0xc5, 0xf4, 0x41, 0x18, 0x77, 0x6f,
                0x8d, 0xb6, 0x1c, 0xea, 0x4f, 0xdf, 0x76, 0x07, 0x9b, 0x93, 0x60, 0x6c, 0x5a, 0x62,
                0x48, 0x00, 0x08, 0x00, 0x01, 0x00, 0x01, 0x00, 0x01, 0x00, 0x03, 0x00, 0x07, 0x65,
                0x63, 0x68, 0x2e, 0x63, 0x6f, 0x6d, 0x00, 0x00,
            ];

            // Case 1: Server has valid cert for ECH public_name "ech.com" (without ECH keys).
            // Client must present outer SNI "ech.com", verify "ech.com" via get_ech_name_override(),
            // and map SSL_R_ECH_REJECTED into TlsError::EchRejected.
            let (_ca1, _ca_key1, pub_leaf, pub_key, roots1) = make_ca_and_leaf(&["ech.com"]);
            let captured = Arc::new(Mutex::new(Vec::new()));
            let pub_acceptor = Arc::new(build_test_acceptor(
                &pub_leaf,
                &pub_key,
                false,
                false,
                Some(Arc::clone(&captured)),
            ));

            let listener1 = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr1 = listener1.local_addr().unwrap();
            let server1 = tokio::spawn(async move {
                let (tcp, _) = listener1.accept().await.unwrap();
                // Server negotiates outer TLS while client rejects missing ECH confirmation.
                let _ = tokio_boring2::accept(&pub_acceptor, tcp).await;
            });

            let client1 = FirefoxBoringConnector::with_roots(roots1).unwrap();
            let ech_cfg = TlsConfig {
                server_name: "inner.example".into(),
                alpn: vec![b"h2".to_vec()],
                ech_config_list: Some(ECH_CONFIG_1_LIST.to_vec()),
                fingerprint: TlsFingerprint::Firefox158,
                ..Default::default()
            };
            let tcp1 = TcpStream::connect(addr1).await.unwrap();
            let err1 = client1.connect(Box::new(tcp1), &ech_cfg).await.unwrap_err();
            assert!(
                matches!(err1, TlsError::EchRejected { .. }),
                "expected TlsError::EchRejected when outer public_name cert matches ech.com, got {err1:?}"
            );
            server1.await.unwrap();

            {
                let hellos = captured.lock().unwrap();
                assert_eq!(hellos.len(), 1);
                assert!(hellos[0].has_ech);
                assert_eq!(hellos[0].outer_sni.as_deref(), Some("ech.com"));
            }

            // Case 2: Server cert covers "inner.example" ONLY (not "ech.com").
            // During ECH rejection, get_ech_name_override() must reject the mismatched public cert
            // rather than trusting inner.example or returning EchRejected.
            let (_ca2, _ca_key2, inner_leaf, inner_key, roots2) =
                make_ca_and_leaf(&["inner.example"]);
            let inner_acceptor = Arc::new(build_test_acceptor(
                &inner_leaf,
                &inner_key,
                false,
                false,
                None,
            ));

            let listener2 = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr2 = listener2.local_addr().unwrap();
            let server2 = tokio::spawn(async move {
                let (tcp, _) = listener2.accept().await.unwrap();
                let _ = tokio_boring2::accept(&inner_acceptor, tcp).await;
            });

            let client2 = FirefoxBoringConnector::with_roots(roots2).unwrap();
            let tcp2 = TcpStream::connect(addr2).await.unwrap();
            let err2 = client2.connect(Box::new(tcp2), &ech_cfg).await.unwrap_err();
            assert!(
                matches!(err2, TlsError::Handshake(_)),
                "expected TlsError::Handshake on mismatched ECH public_name cert, got {err2:?}"
            );
            server2.await.unwrap();

            // Decompressor unit checks
            let mut out = Vec::new();
            let mut enc = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::fast());
            enc.write_all(b"compressed-cert-payload").unwrap();
            let zipped = enc.finish().unwrap();
            super::firefox_boring::ZlibCertDecompressor
                .decompress(&zipped, &mut out)
                .unwrap();
            assert_eq!(out, b"compressed-cert-payload");
            out.clear();
            assert!(
                super::firefox_boring::BrotliCertDecompressor
                    .decompress(&[0xff, 0xff, 0xff], &mut out)
                    .is_err()
            );
        }
    }
}
