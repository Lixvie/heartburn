//! AsyncRead/AsyncWrite tunnel adapters and pre-read prefix buffering (`proxy/tunnel.rs`).

use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use bytes::{Buf, Bytes, BytesMut};
use h2::{RecvStream, SendStream};
use tokio::io::{AsyncRead, AsyncWrite, DuplexStream, ReadBuf};

use crate::proxy::watched::ActivityTracker;

/// Wraps a stream with any initial leftover bytes read ahead during protocol probing
/// or HTTP/1.1 CONNECT response header parsing.
pub struct PrefixedStream<S> {
    prefix: Bytes,
    inner: S,
}

impl<S> PrefixedStream<S> {
    pub fn new(prefix: Bytes, inner: S) -> Self {
        Self { prefix, inner }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for PrefixedStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if !self.prefix.is_empty() {
            let n = self.prefix.len().min(buf.remaining());
            buf.put_slice(&self.prefix[..n]);
            self.prefix.advance(n);
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for PrefixedStream<S> {
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

/// Adapts an HTTP/2 CONNECT bidirectional stream (`h2::SendStream` + `h2::RecvStream`)
/// into a standard Tokio `AsyncRead + AsyncWrite` stream with proper flow control.
pub struct H2TunnelStream {
    send: SendStream<Bytes>,
    recv: RecvStream,
    read_buf: BytesMut,
    tracker: Option<Arc<ActivityTracker>>,
    write_reserved: usize,
    shutting_down: bool,
}

impl H2TunnelStream {
    pub fn new(
        send: SendStream<Bytes>,
        recv: RecvStream,
        tracker: Option<Arc<ActivityTracker>>,
    ) -> Self {
        Self {
            send,
            recv,
            read_buf: BytesMut::new(),
            tracker,
            write_reserved: 0,
            shutting_down: false,
        }
    }
}

impl AsyncRead for H2TunnelStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if !self.read_buf.is_empty() {
            let n = self.read_buf.len().min(buf.remaining());
            buf.put_slice(&self.read_buf.split_to(n));
            if let Some(ref t) = self.tracker {
                t.record_read(n);
            }
            return Poll::Ready(Ok(()));
        }

        loop {
            match Pin::new(&mut self.recv).poll_data(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(None) => return Poll::Ready(Ok(())),
                Poll::Ready(Some(Err(e))) => {
                    return Poll::Ready(Err(io::Error::other(e.to_string())));
                }
                Poll::Ready(Some(Ok(chunk))) => {
                    let len = chunk.len();
                    if len == 0 {
                        continue;
                    }
                    let _ = self.recv.flow_control().release_capacity(len);
                    let to_copy = len.min(buf.remaining());
                    buf.put_slice(&chunk[..to_copy]);
                    if to_copy < len {
                        self.read_buf.extend_from_slice(&chunk[to_copy..]);
                    }
                    if let Some(ref t) = self.tracker {
                        t.record_read(to_copy);
                    }
                    return Poll::Ready(Ok(()));
                }
            }
        }
    }
}

impl AsyncWrite for H2TunnelStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.shutting_down {
            return Poll::Ready(Err(io::Error::from(io::ErrorKind::BrokenPipe)));
        }
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }

        if self.write_reserved == 0 {
            self.send.reserve_capacity(buf.len());
        }

        loop {
            match self.send.poll_capacity(cx) {
                Poll::Pending => {
                    self.write_reserved = buf.len();
                    return Poll::Pending;
                }
                Poll::Ready(None) => {
                    self.write_reserved = 0;
                    return Poll::Ready(Err(io::Error::from(io::ErrorKind::BrokenPipe)));
                }
                Poll::Ready(Some(Err(e))) => {
                    self.write_reserved = 0;
                    return Poll::Ready(Err(io::Error::other(e.to_string())));
                }
                Poll::Ready(Some(Ok(cap))) => {
                    if cap == 0 {
                        self.send.reserve_capacity(buf.len());
                        continue;
                    }
                    self.write_reserved = 0;
                    let n = buf.len().min(cap);
                    let data = Bytes::copy_from_slice(&buf[..n]);
                    self.send
                        .send_data(data, false)
                        .map_err(|e| io::Error::other(e.to_string()))?;
                    if let Some(ref t) = self.tracker {
                        t.record_write_done(0, n);
                    }
                    return Poll::Ready(Ok(n));
                }
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if !self.shutting_down {
            self.shutting_down = true;
            let _ = self.send.send_data(Bytes::new(), true);
        }
        Poll::Ready(Ok(()))
    }
}

/// Bridges a background worker task (e.g. `h3::client::RequestStream` driver)
/// over an in-memory Tokio duplex pipe, closing cleanly on drop.
pub fn duplex_bridge(buf_size: usize) -> (DuplexStream, DuplexStream) {
    tokio::io::duplex(buf_size)
}
