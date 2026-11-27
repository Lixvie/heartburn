//! Socket creation, Android `VpnService.protect` hook, and SOCKS5 upstream dialing.
//!
//! Every outbound TCP connection and UDP socket created by `heartburn-core`
//! passes through [`ProtectedDialer`] so mobile embeddings (Android) can
//! protect file descriptors via `VpnService.protect(fd)` before any packets
//! leave the socket, preventing TUN routing loops.

use std::fmt;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use socket2::{Domain, Protocol, SockAddr, SockRef, Socket, TcpKeepalive, Type};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpSocket, TcpStream, UdpSocket};

use crate::error::DialError;

/// Platform socket file descriptor type (`RawFd` on Unix/Android).
#[cfg(unix)]
pub type SocketFd = std::os::unix::io::RawFd;
#[cfg(not(unix))]
pub type SocketFd = i32;

/// Hook invoked on newly created outbound sockets before `connect()`, `bind()`, or `send()`.
///
/// On Android, pass a callback backed by `VpnService.protect(fd)` so the VPN's
/// own upstream control-plane and tunnel traffic bypasses the TUN device.
pub trait SocketProtector: Send + Sync + fmt::Debug {
    /// Protects the socket descriptor `fd` from being routed through the VPN interface.
    fn protect_fd(&self, fd: SocketFd) -> io::Result<()>;
}

/// Upstream SOCKS5 proxy coordinates for chaining outbound TCP connections.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpstreamSocks5 {
    /// `host:port` address of the upstream SOCKS5 proxy.
    pub addr: String,
    /// Optional RFC 1929 username (1..=255 bytes).
    pub username: String,
    /// Optional RFC 1929 password (1..=255 bytes).
    pub password: String,
}

/// Custom outbound TCP/UDP dialer built on `socket2` and [`SocketProtector`].
#[derive(Clone, Default)]
pub struct ProtectedDialer {
    protector: Option<Arc<dyn SocketProtector>>,
}

impl fmt::Debug for ProtectedDialer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ProtectedDialer")
            .field("has_protector", &self.protector.is_some())
            .finish()
    }
}

impl ProtectedDialer {
    /// Creates a dialer without a socket protection hook.
    pub fn new() -> Self {
        Self { protector: None }
    }

    /// Creates a dialer wrapping an optional [`SocketProtector`].
    pub fn with_protector(protector: Option<Arc<dyn SocketProtector>>) -> Self {
        Self { protector }
    }

    /// Returns a cloned handle to the configured protector, if any.
    pub fn protector(&self) -> Option<Arc<dyn SocketProtector>> {
        self.protector.clone()
    }

    /// Invokes the protection hook (on Unix/Android) for an arbitrary [`SocketFd`].
    pub fn protect_raw_fd(&self, fd: SocketFd) -> Result<(), DialError> {
        if let Some(ref p) = self.protector {
            p.protect_fd(fd).map_err(DialError::Protect)?;
        }
        Ok(())
    }

    /// Connects a TCP stream to `addr` with socket protection, keepalive, and timeout.
    pub async fn connect_tcp(
        &self,
        addr: SocketAddr,
        timeout: Duration,
    ) -> Result<TcpStream, DialError> {
        Box::pin(async move {
            let sock = if addr.is_ipv4() {
                TcpSocket::new_v4()?
            } else {
                TcpSocket::new_v6()?
            };

            #[cfg(unix)]
            {
                use std::os::unix::io::AsRawFd;
                self.protect_raw_fd(sock.as_raw_fd())?;
            }

            // Configure keepalive before connecting so idle sessions detect half-open drops.
            let ka = TcpKeepalive::new()
                .with_time(Duration::from_secs(30))
                .with_interval(Duration::from_secs(10));
            let _ = SockRef::from(&sock).set_tcp_keepalive(&ka);

            let stream = tokio::time::timeout(timeout, sock.connect(addr))
                .await
                .map_err(|_| DialError::Timeout)??;
            let _ = stream.set_nodelay(true);
            Ok(stream)
        })
        .await
    }

    /// Creates, protects, and binds a non-blocking `std::net::UdpSocket` ready for
    /// `quinn` or [`tokio::net::UdpSocket::from_std`].
    pub fn bind_std_udp(&self, bind_addr: SocketAddr) -> Result<std::net::UdpSocket, DialError> {
        let domain = if bind_addr.is_ipv4() {
            Domain::IPV4
        } else {
            Domain::IPV6
        };
        let sock = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;
        sock.set_nonblocking(true)?;

        #[cfg(unix)]
        {
            use std::os::unix::io::AsRawFd;
            self.protect_raw_fd(sock.as_raw_fd())?;
        }

        sock.bind(&SockAddr::from(bind_addr))?;
        Ok(sock.into())
    }

    /// Creates a protected ephemeral UDP socket matched to `peer_family` (`V4` or `V6`).
    pub fn bind_udp_for_peer(&self, peer_is_ipv6: bool) -> Result<UdpSocket, DialError> {
        let bind_ip = if peer_is_ipv6 {
            IpAddr::V6(Ipv6Addr::UNSPECIFIED)
        } else {
            IpAddr::V4(Ipv4Addr::UNSPECIFIED)
        };
        let std_sock = self.bind_std_udp(SocketAddr::new(bind_ip, 0))?;
        Ok(UdpSocket::from_std(std_sock)?)
    }

    /// Connects a protected UDP socket to `peer` for DNS or single-target UDP I/O.
    pub async fn connect_udp(&self, peer: SocketAddr) -> Result<UdpSocket, DialError> {
        let sock = self.bind_udp_for_peer(peer.is_ipv6())?;
        sock.connect(peer).await?;
        Ok(sock)
    }

    /// Opens a TCP tunnel to `target_host:target_port` chained through `proxy` via SOCKS5.
    ///
    /// Domain targets are passed directly as ATYP `0x03` so DNS resolution happens
    /// on the upstream SOCKS5 proxy side.
    pub async fn connect_via_socks5(
        &self,
        proxy: &UpstreamSocks5,
        proxy_addr: SocketAddr,
        target_host: &str,
        target_port: u16,
        timeout: Duration,
    ) -> Result<TcpStream, DialError> {
        Box::pin(async move {
            let mut stream = self.connect_tcp(proxy_addr, timeout).await?;
            tokio::time::timeout(
                timeout,
                socks5_handshake(
                    &mut stream,
                    &proxy.username,
                    &proxy.password,
                    target_host,
                    target_port,
                ),
            )
            .await
            .map_err(|_| DialError::Timeout)??;
            Ok(stream)
        })
        .await
    }
}

async fn socks5_handshake(
    stream: &mut TcpStream,
    username: &str,
    password: &str,
    target_host: &str,
    target_port: u16,
) -> Result<(), DialError> {
    Box::pin(async move {
        let use_auth = !username.is_empty() || !password.is_empty();
        let methods: &[u8] = if use_auth { &[0x05, 0x02, 0x00, 0x02] } else { &[0x05, 0x01, 0x00] };
        stream.write_all(methods).await?;

        let mut method_rep = [0u8; 2];
        stream.read_exact(&mut method_rep).await?;
        if method_rep[0] != 0x05 {
            return Err(DialError::Socks5(format!(
                "unexpected SOCKS version {} in greeting reply",
                method_rep[0]
            )));
        }

        match method_rep[1] {
            0x00 => {}
            0x02 if use_auth => {
                if username.len() > 255 || password.len() > 255 {
                    return Err(DialError::Socks5(
                        "SOCKS5 username/password exceed 255 bytes".into(),
                    ));
                }
                let mut auth_req = Vec::with_capacity(3 + username.len() + password.len());
                auth_req.push(0x01);
                auth_req.push(username.len() as u8);
                auth_req.extend_from_slice(username.as_bytes());
                auth_req.push(password.len() as u8);
                auth_req.extend_from_slice(password.as_bytes());
                stream.write_all(&auth_req).await?;

                let mut auth_rep = [0u8; 2];
                stream.read_exact(&mut auth_rep).await?;
                if auth_rep[1] != 0x00 {
                    return Err(DialError::Socks5(
                        "upstream SOCKS5 authentication failed".into(),
                    ));
                }
            }
            0xff => {
                return Err(DialError::Socks5(
                    "upstream SOCKS5 rejected authentication methods".into(),
                ));
            }
            other => {
                return Err(DialError::Socks5(format!(
                    "upstream SOCKS5 chose unsupported auth method {other:#x}"
                )));
            }
        }

        let mut req = Vec::with_capacity(7 + target_host.len());
        req.extend_from_slice(&[0x05, 0x01, 0x00]); // VER=5, CMD=CONNECT, RSV=0

        if let Ok(ip) = target_host.parse::<IpAddr>() {
            match ip {
                IpAddr::V4(v4) => {
                    req.push(0x01);
                    req.extend_from_slice(&v4.octets());
                }
                IpAddr::V6(v6) => {
                    req.push(0x04);
                    req.extend_from_slice(&v6.octets());
                }
            }
        } else {
            if target_host.len() > 255 {
                return Err(DialError::Socks5("target host exceeds 255 bytes".into()));
            }
            req.push(0x03);
            req.push(target_host.len() as u8);
            req.extend_from_slice(target_host.as_bytes());
        }
        req.extend_from_slice(&target_port.to_be_bytes());
        stream.write_all(&req).await?;

        let mut hdr = [0u8; 4];
        stream.read_exact(&mut hdr).await?;
        if hdr[0] != 0x05 {
            return Err(DialError::Socks5(format!(
                "unexpected SOCKS version {} in CONNECT reply",
                hdr[0]
            )));
        }
        if hdr[1] != 0x00 {
            return Err(DialError::Socks5(format!(
                "upstream SOCKS5 CONNECT rejected with code {:#x}",
                hdr[1]
            )));
        }

        // Consume BND.ADDR + BND.PORT before returning the tunnel stream.
        let skip_len = match hdr[3] {
            0x01 => 4 + 2,
            0x04 => 16 + 2,
            0x03 => {
                let mut dlen = [0u8; 1];
                stream.read_exact(&mut dlen).await?;
                usize::from(dlen[0]) + 2
            }
            other => {
                return Err(DialError::Socks5(format!(
                    "unknown SOCKS5 ATYP {other:#x} in CONNECT reply"
                )));
            }
        };
        let mut discard = vec![0u8; skip_len];
        stream.read_exact(&mut discard).await?;
        Ok(())
    })
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    #[cfg(unix)]
    #[derive(Debug, Default)]
    struct CountingProtector {
        calls: std::sync::atomic::AtomicUsize,
    }

    #[cfg(unix)]
    impl SocketProtector for CountingProtector {
        fn protect_fd(&self, fd: SocketFd) -> io::Result<()> {
            assert!(fd >= 0);
            self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(())
        }
    }

    #[tokio::test]
    async fn protected_dialer_connects_tcp_and_udp() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let dialer = ProtectedDialer::new();
        let (client, server) = tokio::join!(
            dialer.connect_tcp(addr, Duration::from_secs(2)),
            tokio::time::timeout(Duration::from_secs(2), listener.accept())
        );
        let mut c = client.unwrap();
        let (mut s, _) = server.unwrap().unwrap();
        c.write_all(b"ping").await.unwrap();
        let mut buf = [0u8; 4];
        s.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"ping");

        let udp = dialer.connect_udp(addr).await.unwrap();
        assert!(udp.local_addr().unwrap().is_ipv4());
    }

    #[tokio::test]
    async fn socks5_client_handshake_forwards_domain() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = listener.local_addr().unwrap();

        let server_task = tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.unwrap();
            let mut greet = [0u8; 3];
            s.read_exact(&mut greet).await.unwrap();
            assert_eq!(&greet, &[0x05, 0x01, 0x00]);
            s.write_all(&[0x05, 0x00]).await.unwrap();

            let mut hdr = [0u8; 4];
            s.read_exact(&mut hdr).await.unwrap();
            assert_eq!(&hdr, &[0x05, 0x01, 0x00, 0x03]);
            let mut len = [0u8; 1];
            s.read_exact(&mut len).await.unwrap();
            let mut host = vec![0u8; usize::from(len[0])];
            s.read_exact(&mut host).await.unwrap();
            assert_eq!(&host, b"example.com");
            let mut port = [0u8; 2];
            s.read_exact(&mut port).await.unwrap();
            assert_eq!(u16::from_be_bytes(port), 443);

            s.write_all(&[0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0, 0])
                .await
                .unwrap();
            s.write_all(b"ok").await.unwrap();
        });

        let dialer = ProtectedDialer::new();
        let proxy = UpstreamSocks5 {
            addr: proxy_addr.to_string(),
            username: String::new(),
            password: String::new(),
        };
        let mut tun = dialer
            .connect_via_socks5(&proxy, proxy_addr, "example.com", 443, Duration::from_secs(2))
            .await
            .unwrap();
        let mut msg = [0u8; 2];
        tun.read_exact(&mut msg).await.unwrap();
        assert_eq!(&msg, b"ok");
        server_task.await.unwrap();
    }
}
