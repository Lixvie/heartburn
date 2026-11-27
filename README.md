# heartburn

Massive shoutout to Incos on ntc.party and [UjuiUjuMandan/firefox-vpn-client](https://github.com/UjuiUjuMandan/firefox-vpn-client).

Lean, modular Rust upstream proxy engine built to power **`sing-box`** on Windows (in-process Tauri v2 embedding) and Android (UniFFI / Kotlin `VpnService`).

## License

Dual-licensed under either of:

- **MIT License** ([LICENSE-MIT](LICENSE-MIT))
- **Apache License, Version 2.0** ([LICENSE-APACHE](LICENSE-APACHE))

at your option.

## Workspace Architecture

- **`crates/heartburn-core`**: Platform-agnostic async Rust/Tokio library crate with zero desktop-UI, Tauri, Wintun, or JNI dependencies:
  - **Storage-agnostic persistence**: `Storage` trait (`FsStorage` rooted at caller-supplied `data_dir` or `MemoryStorage` for embedded/testing use; AES-256-GCM encrypted account credentials in `secret.key` / `credentials.json`).
  - **Android-ready networking**: All outbound TCP and UDP sockets pass through `ProtectedDialer` built on `socket2`, invoking an optional `SocketProtector` callback (`RawFd` on Unix/Android) before `connect()`, `bind()`, or `send()` for `VpnService.protect(fd)`.
  - **Control-plane & Auth**: Firefox Accounts SRP/PBKDF2/HKDF + HAWK signing, direct/PKCE OAuth2 + refresh, Fastly 406 PoW/captcha challenge solver, Guardian ProxyPass JWT claim clock-skew anchoring, HTTP 451 `//api/...` retry, cached evasion waterfall, and `switch_threshold_percent` multi-account failover.
  - **Anti-DPI & Bootstrap DNS**: DoH / DoT / plain internal bootstrap resolver (for control-plane and Fastly edge names only), Happy Eyeballs dialing (`300ms` stagger, 10m address penalties), block-page IP filtering, TLS 1.3 ECH (`HTTPS` RR lookup + pure-Rust RFC 9180 HPKE via `ring`), `hellosplit` (`auto`, `sni`, `first-byte`, `record`), and optional personal HTTPS `api_relay` (including `.workers.dev` TLS 1.2 + `chatgpt.com` edge fallback).
  - **Upstream Transports**: HTTP/2 (`1 MiB` window, adaptive 5s PING + `CONNECT-UDP`), HTTP/1.1 (`1` pre-warmed spare connection), HTTP/3 over QUIC (`quinn` with protected UDP sockets, `InitialMTU = 1200`, `15s` keepalive, Happy Eyeballs candidate racing, fast `3s` fallback to HTTP/2), `ServerFailover` stand-in selection, and idle sleep/wake.
  - **Local Loopback Listener**: Lightweight SOCKS5 (`CONNECT` + `UDP ASSOCIATE` constrained to Fastly's allowed UDP ports `80, 443, 3478, 8080, 8443, 49152-65534`) + HTTP `CONNECT` / absolute-form proxy tailored as a `sing-box` outbound (`socks` / `http`). Client DNS is handled externally by `sing-box`.
- **`crates/heartburn-ffi`**: Thin UniFFI (`0.29`) wrapper exposing `FfiEngine`, `FfiSocketProtector`, `FfiEventListener`, and typed records/errors for Android Kotlin (`cdylib` + `rlib`).
- **`crates/heartburn-cli`**: Minimal standalone debugging CLI (`heartburn`). Running with no arguments prints help and exits `0` without altering system network settings.

## TLS Fingerprinting Feature (`firefox-tls`)

- **Default (`default = []`)**: Uses `rustls` (`ring` crypto provider) with Mozilla WebPKI roots, embedded GlobalSign Root R46/E46 CA certificates, and pure-Rust TLS 1.3 ECH (`hpke_ring`). Compiles everywhere out of the box with zero C/C++/Perl/NASM toolchain requirements.
- **`--features firefox-tls`**: Enables `boring2` + `tokio-boring2` (`FirefoxBoringConnector`) for desktop Firefox 158 ClientHello parity (cipher suites, curves including `X25519MLKEM768`, key shares, signature algorithms, OCSP/SCT, delegated credentials, record size limit, zlib/brotli cert decompression, and ECH GREASE). Requires BoringSSL build prerequisites (`clang` / `libclang`, `cmake`, `nasm`, `perl`, and on Android the Android NDK with `cargo-ndk`).

## Quick Verification & Usage

```bash
# Run unit & loopback integration tests across the workspace
cargo test --workspace

# Build or test with exact Firefox TLS fingerprinting enabled
cargo test --workspace --features firefox-tls

# Inspect standalone debugging CLI usage (exits cleanly without changing OS proxy settings)
cargo run -p heartburn-cli

# Example: validate or generate default config.json inside ./user-data
cargo run -p heartburn-cli -- --data-dir ./user-data validate-config

# Cross-compile core/FFI for Android arm64-v8a (once Android NDK + cargo-ndk are installed)
cargo ndk -t arm64-v8a build -p heartburn-ffi --release
```

### Example `sing-box` Outbound

Point `sing-box` to `heartburn`'s local loopback SOCKS5 listener (`127.0.0.1:10810` by default) while letting `sing-box` handle TUN capture, routing rules, and DoH/DNS over TCP 443:

```json
{
  "type": "socks",
  "tag": "mozilla-proxy",
  "server": "127.0.0.1",
  "server_port": 10810,
  "version": "5"
}
```
