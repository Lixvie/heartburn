//! TLS ClientHello anti-DPI splitting (`hellosplit`).
//!
//! Splits the initial TLS ClientHello write across TCP segments or multiple TLS
//! handshake records so SNI-inspecting middleboxes miss the server name.

use std::collections::VecDeque;
use std::io;
use std::pin::Pin;
use std::str::FromStr;
use std::task::{Context, Poll};

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// Strategy used when emitting the initial TLS ClientHello flight.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum HelloSplitMode {
    /// Let the transport race/choose automatically (`"auto"`).
    #[default]
    Auto,
    /// Disable splitting (`"off"` or empty string).
    Off,
    /// Split TCP writes inside the TLS SNI hostname (`"sni"`).
    Sni,
    /// Send the first byte of ClientHello separately (`"first-byte"`).
    FirstByte,
    /// Split ClientHello into two separate TLS handshake records (`"record"`).
    Record,
}

impl HelloSplitMode {
    /// Canonical config string form.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::Off => "off",
            Self::Sni => "sni",
            Self::FirstByte => "first-byte",
            Self::Record => "record",
        }
    }

    /// Returns `true` when splitting behavior is explicitly active (not `Off`).
    pub const fn is_active(self) -> bool {
        !matches!(self, Self::Off)
    }
}

impl FromStr for HelloSplitMode {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_ascii_lowercase().as_str() {
            "" | "off" => Ok(Self::Off),
            "auto" => Ok(Self::Auto),
            "sni" => Ok(Self::Sni),
            "first-byte" => Ok(Self::FirstByte),
            "record" => Ok(Self::Record),
            other => Err(format!(
                "invalid hello_split mode {other:?}: expected auto, off, sni, first-byte, or record"
            )),
        }
    }
}

/// Computes the byte offset inside a serialized TLS record where the SNI
/// `host_name` payload begins, if `buf` holds a complete or partial ClientHello
/// with an SNI extension.
pub fn find_sni_offset(buf: &[u8]) -> Option<usize> {
    // TLS record header (5 bytes): ContentType=0x16 (Handshake), Version(2), Length(2)
    if buf.len() < 9 || buf[0] != 0x16 {
        return None;
    }
    // Handshake header: msg_type=0x01 (ClientHello), length(3)
    if buf[5] != 0x01 {
        return None;
    }

    // Offset inside ClientHello body:
    // 5 (record hdr) + 4 (handshake hdr) + 2 (legacy_version) + 32 (random) = 43
    let mut pos = 43;
    let sid_len = *buf.get(pos)? as usize;
    pos += 1 + sid_len;

    let cs_hi = *buf.get(pos)? as usize;
    let cs_lo = *buf.get(pos + 1)? as usize;
    let cs_len = (cs_hi << 8) | cs_lo;
    pos += 2 + cs_len;

    let comp_len = *buf.get(pos)? as usize;
    pos += 1 + comp_len;

    let ext_hi = *buf.get(pos)? as usize;
    let ext_lo = *buf.get(pos + 1)? as usize;
    let ext_total = (ext_hi << 8) | ext_lo;
    pos += 2;
    let ext_end = pos.saturating_add(ext_total).min(buf.len());

    while pos + 4 <= ext_end {
        let ext_type = ((buf[pos] as u16) << 8) | (buf[pos + 1] as u16);
        let ext_len = ((buf[pos + 2] as usize) << 8) | (buf[pos + 3] as usize);
        let data_start = pos + 4;
        if ext_type == 0x0000 {
            // ServerNameList: list_len(2), name_type(1)=0x00, name_len(2), host_name...
            if data_start + 5 <= buf.len() && buf[data_start + 2] == 0x00 {
                return Some(data_start + 5);
            }
            return None;
        }
        pos = data_start.saturating_add(ext_len);
    }
    None
}

/// Splits an initial ClientHello buffer according to `mode` into sequential
/// chunks ready to be written individually to the underlying stream.
pub fn split_client_hello(buf: &[u8], mode: HelloSplitMode) -> Vec<Vec<u8>> {
    if buf.len() <= 1 || matches!(mode, HelloSplitMode::Off) {
        return vec![buf.to_vec()];
    }

    // "auto" defaults cleanly to "sni" fragmentation when an explicit split stream is used.
    let effective = match mode {
        HelloSplitMode::Auto => HelloSplitMode::Sni,
        other => other,
    };

    match effective {
        HelloSplitMode::Off | HelloSplitMode::Auto => vec![buf.to_vec()],
        HelloSplitMode::FirstByte => vec![buf[..1].to_vec(), buf[1..].to_vec()],
        HelloSplitMode::Sni => match find_sni_offset(buf) {
            Some(sni_start) if sni_start + 1 < buf.len() => vec![
                buf[..sni_start].to_vec(),
                buf[sni_start..sni_start + 1].to_vec(),
                buf[sni_start + 1..].to_vec(),
            ],
            _ => vec![buf[..1].to_vec(), buf[1..].to_vec()],
        },
        HelloSplitMode::Record => split_into_two_tls_records(buf),
    }
}

fn split_into_two_tls_records(buf: &[u8]) -> Vec<Vec<u8>> {
    if buf.len() < 6 || buf[0] != 0x16 {
        return vec![buf.to_vec()];
    }
    let record_len = ((buf[3] as usize) << 8) | (buf[4] as usize);
    if 5 + record_len > buf.len() {
        return split_client_hello(buf, HelloSplitMode::Sni);
    }

    let cut = find_sni_offset(buf)
        .map(|s| s + 1)
        .filter(|&c| c > 5 && c < 5 + record_len)
        .unwrap_or_else(|| 5 + (record_len / 2).max(1));

    let part1_payload = &buf[5..cut];
    let part2_payload = &buf[cut..5 + record_len];
    let trailing = &buf[5 + record_len..];

    let mut rec1 = Vec::with_capacity(5 + part1_payload.len());
    rec1.push(0x16);
    rec1.push(buf[1]);
    rec1.push(buf[2]);
    rec1.extend_from_slice(&(part1_payload.len() as u16).to_be_bytes());
    rec1.extend_from_slice(part1_payload);

    let mut rec2 = Vec::with_capacity(5 + part2_payload.len() + trailing.len());
    rec2.push(0x16);
    rec2.push(buf[1]);
    rec2.push(buf[2]);
    rec2.extend_from_slice(&(part2_payload.len() as u16).to_be_bytes());
    rec2.extend_from_slice(part2_payload);
    if !trailing.is_empty() {
        rec2.extend_from_slice(trailing);
    }

    vec![rec1, rec2]
}

/// Async stream wrapper that fragments only the very first ClientHello `write()`,
/// passing all subsequent reads and writes directly through unchanged.
pub struct SplitStream<S> {
    inner: S,
    mode: HelloSplitMode,
    first_write_done: bool,
    pending_chunks: VecDeque<Vec<u8>>,
    current_offset: usize,
    reported_first_len: usize,
}

impl<S> SplitStream<S> {
    /// Wraps `inner` with the given [`HelloSplitMode`].
    pub fn new(inner: S, mode: HelloSplitMode) -> Self {
        Self {
            inner,
            mode,
            first_write_done: !mode.is_active(),
            pending_chunks: VecDeque::new(),
            current_offset: 0,
            reported_first_len: 0,
        }
    }

    /// Consumes the wrapper and returns the inner stream.
    pub fn into_inner(self) -> S {
        self.inner
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for SplitStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for SplitStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if this.first_write_done && this.pending_chunks.is_empty() {
            return Pin::new(&mut this.inner).poll_write(cx, buf);
        }

        if this.pending_chunks.is_empty() {
            if buf.first() == Some(&0x16) {
                let chunks = split_client_hello(buf, this.mode);
                this.pending_chunks = chunks.into();
                this.current_offset = 0;
                this.reported_first_len = buf.len();
                this.first_write_done = true;
            } else {
                this.first_write_done = true;
                return Pin::new(&mut this.inner).poll_write(cx, buf);
            }
        }

        while !this.pending_chunks.is_empty() {
            let front_len = this.pending_chunks[0].len();
            if this.current_offset >= front_len {
                this.pending_chunks.pop_front();
                this.current_offset = 0;
                continue;
            }
            let write_poll = {
                let slice = &this.pending_chunks[0][this.current_offset..];
                Pin::new(&mut this.inner).poll_write(cx, slice)
            };
            match write_poll {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(e)) => {
                    this.pending_chunks.clear();
                    return Poll::Ready(Err(e));
                }
                Poll::Ready(Ok(0)) => {
                    this.pending_chunks.clear();
                    return Poll::Ready(Err(io::Error::from(io::ErrorKind::WriteZero)));
                }
                Poll::Ready(Ok(n)) => {
                    this.current_offset += n;
                    if this.current_offset >= front_len {
                        this.pending_chunks.pop_front();
                        this.current_offset = 0;
                        // Flush between ClientHello chunks so TCP/middleboxes observe separate segments.
                        let _ = Pin::new(&mut this.inner).poll_flush(cx);
                    }
                }
            }
        }

        let total = this.reported_first_len;
        this.reported_first_len = 0;
        Poll::Ready(Ok(total))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if !self.pending_chunks.is_empty() {
            match self.as_mut().poll_write(cx, &[]) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Ready(Ok(_)) => {}
            }
        }
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn fake_client_hello(sni: &str) -> Vec<u8> {
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
        body.extend_from_slice(&[0x03, 0x03]); // legacy_version
        body.extend_from_slice(&[0xaa; 32]); // random
        body.push(0x00); // session_id_len
        body.extend_from_slice(&2u16.to_be_bytes()); // cipher_suites_len
        body.extend_from_slice(&[0x13, 0x01]);
        body.push(0x01); // compression len
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

    #[test]
    fn finds_sni_and_splits_all_modes() {
        let ch = fake_client_hello("vpn.mozilla.org");
        let off = find_sni_offset(&ch).expect("sni offset");
        assert_eq!(&ch[off..off + 15], b"vpn.mozilla.org");

        let fb = split_client_hello(&ch, HelloSplitMode::FirstByte);
        assert_eq!(fb.len(), 2);
        assert_eq!(fb[0].len(), 1);
        assert_eq!(fb.concat(), ch);

        let sni = split_client_hello(&ch, HelloSplitMode::Sni);
        assert_eq!(sni.len(), 3);
        assert_eq!(sni[1], b"v");
        assert_eq!(sni.concat(), ch);

        let recs = split_client_hello(&ch, HelloSplitMode::Record);
        assert_eq!(recs.len(), 2);
        assert_eq!(recs[0][0], 0x16);
        assert_eq!(recs[1][0], 0x16);
        let reassembled_payload = [&recs[0][5..], &recs[1][5..]].concat();
        assert_eq!(reassembled_payload, ch[5..]);
    }

    #[tokio::test]
    async fn split_stream_writes_exact_bytes() {
        let ch = fake_client_hello("example.org");
        let (duplex_w, mut duplex_r) = tokio::io::duplex(4096);
        let mut s = SplitStream::new(duplex_w, HelloSplitMode::Sni);
        s.write_all(&ch).await.unwrap();
        s.write_all(b"app-data").await.unwrap();
        drop(s);

        let mut out = Vec::new();
        duplex_r.read_to_end(&mut out).await.unwrap();
        let mut expected = ch;
        expected.extend_from_slice(b"app-data");
        assert_eq!(out, expected);
    }
}
