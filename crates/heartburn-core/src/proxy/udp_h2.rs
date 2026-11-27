//! RFC 9298 `CONNECT-UDP` over HTTP/2 + RFC 9297 HTTP Datagram capsule framing (`proxy/udp_h2.go`).

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use bytes::{Buf, Bytes, BytesMut};
use h2::client::SendRequest;
use h2::ext::Protocol;
use http::{HeaderValue, Method, Request};
use percent_encoding::{AsciiSet, NON_ALPHANUMERIC, utf8_percent_encode};
use tokio::sync::mpsc;

use crate::error::ProxyError;
use crate::proxy::{UdpTunnel, is_allowed_udp_port};

const CAPSULE_TYPE_DATAGRAM: u64 = 0x00;
const CONTEXT_ID_UDP: u64 = 0x00;
const MAX_UDP_CAPSULE_PAYLOAD: usize = 65536;
const UDP_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(15);
const UDP_IDLE_WRITE_CHANNEL: usize = 128;

const PATH_ENCODE_SET: &AsciiSet = &NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'.')
    .remove(b'_')
    .remove(b'~');

/// Encodes an unsigned 62-bit QUIC variable-length integer (RFC 9000 Section 16).
pub fn encode_quic_varint(val: u64, out: &mut Vec<u8>) -> Result<(), ProxyError> {
    if val < (1 << 6) {
        out.push(val as u8);
    } else if val < (1 << 14) {
        out.extend_from_slice(&((val as u16) | 0x4000).to_be_bytes());
    } else if val < (1 << 30) {
        out.extend_from_slice(&((val as u32) | 0x8000_0000).to_be_bytes());
    } else if val < (1 << 62) {
        out.extend_from_slice(&(val | 0xC000_0000_0000_0000).to_be_bytes());
    } else {
        return Err(ProxyError::Protocol("QUIC varint overflow".into()));
    }
    Ok(())
}

/// Attempts to decode a QUIC varint from `buf`. Returns `Ok(None)` if more bytes are needed.
pub fn decode_quic_varint(buf: &[u8]) -> Result<Option<(u64, usize)>, ProxyError> {
    if buf.is_empty() {
        return Ok(None);
    }
    let prefix = buf[0] >> 6;
    let len = 1usize << prefix;
    if buf.len() < len {
        return Ok(None);
    }
    let val = match len {
        1 => u64::from(buf[0] & 0x3f),
        2 => u64::from(u16::from_be_bytes([buf[0] & 0x3f, buf[1]])),
        4 => u64::from(u32::from_be_bytes([
            buf[0] & 0x3f,
            buf[1],
            buf[2],
            buf[3],
        ])),
        8 => u64::from_be_bytes([
            buf[0] & 0x3f,
            buf[1],
            buf[2],
            buf[3],
            buf[4],
            buf[5],
            buf[6],
            buf[7],
        ]),
        _ => return Err(ProxyError::Protocol("unreachable varint length".into())),
    };
    Ok(Some((val, len)))
}

/// Frames a UDP payload into an HTTP Datagram `CAPSULE` (`Type=0`, `Length`, `ContextID=0`, `Payload`).
pub fn encode_datagram_capsule(payload: &[u8]) -> Result<Bytes, ProxyError> {
    let body_len = 1usize + payload.len(); // 1-byte ContextID(0) + payload
    let mut out = Vec::with_capacity(6 + payload.len());
    encode_quic_varint(CAPSULE_TYPE_DATAGRAM, &mut out)?;
    encode_quic_varint(body_len as u64, &mut out)?;
    encode_quic_varint(CONTEXT_ID_UDP, &mut out)?;
    out.extend_from_slice(payload);
    Ok(Bytes::from(out))
}

/// Consumes complete capsules from `buf`, returning extracted Context-ID-0 UDP payloads.
pub fn drain_datagram_capsules(buf: &mut BytesMut) -> Result<Vec<Vec<u8>>, ProxyError> {
    let mut packets = Vec::new();
    while let Some((cap_type, type_len)) = decode_quic_varint(buf)? {
        let Some((cap_len_u64, len_len)) = decode_quic_varint(&buf[type_len..])? else {
            break;
        };
        let cap_len = usize::try_from(cap_len_u64)
            .map_err(|_| ProxyError::Protocol("capsule length exceeds usize".into()))?;
        if cap_len > MAX_UDP_CAPSULE_PAYLOAD {
            return Err(ProxyError::Protocol("oversized HTTP capsule".into()));
        }
        let total = type_len + len_len + cap_len;
        if buf.len() < total {
            break;
        }
        buf.advance(type_len + len_len);
        let payload_frame = buf.split_to(cap_len);
        if cap_type == CAPSULE_TYPE_DATAGRAM
            && let Some((ctx_id, ctx_len)) = decode_quic_varint(&payload_frame)?
            && ctx_id == CONTEXT_ID_UDP
        {
            packets.push(payload_frame[ctx_len..].to_vec());
        }
    }
    Ok(packets)
}

/// Opens a MASQUE `CONNECT-UDP` tunnel over an active HTTP/2 `SendRequest` session.
pub async fn open_h2_connect_udp(
    sender: SendRequest<Bytes>,
    proxy_authority: &str,
    user_agent: &str,
    proxy_pass: &str,
    target_host: &str,
    target_port: u16,
) -> Result<UdpTunnel, ProxyError> {
    if !is_allowed_udp_port(target_port) {
        return Err(ProxyError::PortRejected(target_port));
    }

    let pct_host = utf8_percent_encode(target_host.trim_matches(['[', ']']), PATH_ENCODE_SET);
    let uri = format!("https://{proxy_authority}/.well-known/masque/udp/{pct_host}/{target_port}/");

    let mut ready = sender
        .ready()
        .await
        .map_err(|e| ProxyError::Transport(format!("H2 CONNECT-UDP not ready: {e}")))?;

    let mut req = Request::builder()
        .method(Method::CONNECT)
        .uri(uri)
        .header("capsule-protocol", "?1")
        .header(
            http::header::PROXY_AUTHORIZATION,
            HeaderValue::from_str(&format!("Bearer {proxy_pass}"))
                .map_err(|_| ProxyError::Protocol("invalid ProxyPass header".into()))?,
        )
        .header(
            http::header::USER_AGENT,
            HeaderValue::from_str(user_agent)
                .map_err(|_| ProxyError::Protocol("invalid User-Agent header".into()))?,
        )
        .body(())
        .map_err(|e| ProxyError::Protocol(format!("build CONNECT-UDP request: {e}")))?;
    req.extensions_mut()
        .insert(Protocol::from_static("connect-udp"));

    let (resp_fut, mut h2_send) = ready
        .send_request(req, false)
        .map_err(|e| ProxyError::Transport(format!("H2 CONNECT-UDP send failed: {e}")))?;

    let resp = tokio::time::timeout(UDP_HANDSHAKE_TIMEOUT, resp_fut)
        .await
        .map_err(|_| ProxyError::Transport("H2 CONNECT-UDP handshake timed out".into()))?
        .map_err(|e| ProxyError::Transport(format!("H2 CONNECT-UDP response error: {e}")))?;

    let status = resp.status();
    if !status.is_success() {
        if matches!(status.as_u16(), 401 | 402 | 407) {
            return Err(ProxyError::AuthFailed);
        }
        return Err(ProxyError::UpstreamStatus {
            status: status.as_u16(),
            message: format!("CONNECT-UDP rejected with {status}"),
        });
    }

    let mut h2_recv = resp.into_body();
    let (up_tx, mut up_rx) = mpsc::channel::<Vec<u8>>(UDP_IDLE_WRITE_CHANNEL);
    let (down_tx, down_rx) = mpsc::channel::<Vec<u8>>(UDP_IDLE_WRITE_CHANNEL);
    let closed = Arc::new(AtomicBool::new(false));
    let closed_writer = Arc::clone(&closed);
    let closed_reader = Arc::clone(&closed);

    tokio::spawn(async move {
        while let Some(pkt) = up_rx.recv().await {
            let Ok(capsule) = encode_datagram_capsule(&pkt) else {
                continue;
            };
            h2_send.reserve_capacity(capsule.len());
            let mut off = 0usize;
            while off < capsule.len() {
                match futures::future::poll_fn(|cx| h2_send.poll_capacity(cx)).await {
                    Some(Ok(cap)) if cap > 0 => {
                        let end = (off + cap).min(capsule.len());
                        if h2_send.send_data(capsule.slice(off..end), false).is_err() {
                            closed_writer.store(true, Ordering::Relaxed);
                            return;
                        }
                        off = end;
                    }
                    Some(Ok(_)) => continue,
                    _ => {
                        closed_writer.store(true, Ordering::Relaxed);
                        return;
                    }
                }
            }
        }
        let _ = h2_send.send_data(Bytes::new(), true);
        closed_writer.store(true, Ordering::Relaxed);
    });

    tokio::spawn(async move {
        let mut buf = BytesMut::new();
        while let Some(chunk_res) = h2_recv.data().await {
            let Ok(chunk) = chunk_res else {
                break;
            };
            let _ = h2_recv.flow_control().release_capacity(chunk.len());
            buf.extend_from_slice(&chunk);
            match drain_datagram_capsules(&mut buf) {
                Ok(pkts) => {
                    for pkt in pkts {
                        if down_tx.send(pkt).await.is_err() {
                            closed_reader.store(true, Ordering::Relaxed);
                            return;
                        }
                    }
                }
                Err(_) => break,
            }
        }
        closed_reader.store(true, Ordering::Relaxed);
    });

    Ok(UdpTunnel {
        tx: up_tx,
        rx: down_rx,
        closed,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrips_quic_varints_and_capsules() {
        for v in [0u64, 1, 63, 64, 16383, 16384, 1_000_000, (1 << 62) - 1] {
            let mut encoded = Vec::new();
            encode_quic_varint(v, &mut encoded).unwrap();
            let (dec, consumed) = decode_quic_varint(&encoded).unwrap().unwrap();
            assert_eq!(dec, v);
            assert_eq!(consumed, encoded.len());
        }

        let p1 = encode_datagram_capsule(b"hello-udp").unwrap();
        let p2 = encode_datagram_capsule(b"world").unwrap();
        let mut buf = BytesMut::new();
        // Partial delivery check
        buf.extend_from_slice(&p1[..4]);
        assert!(drain_datagram_capsules(&mut buf).unwrap().is_empty());
        buf.extend_from_slice(&p1[4..]);
        buf.extend_from_slice(&p2);

        let out = drain_datagram_capsules(&mut buf).unwrap();
        assert_eq!(out, vec![b"hello-udp".to_vec(), b"world".to_vec()]);
        assert!(buf.is_empty());
    }
}
