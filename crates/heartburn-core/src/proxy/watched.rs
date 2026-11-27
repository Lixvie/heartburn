//! Adaptive traffic-aware stream wrapper (`proxy/upstream_h2.go` watchedConn).
//!
//! Records recent reads and large queued upload flights so HTTP/2 PING liveness
//! checks are suppressed while active transfers are making progress or saturating
//! the uplink.

use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

const UPLOAD_SUPPRESS_THRESHOLD_BYTES: usize = 256 * 1024;
const READ_RECENT_WINDOW: Duration = Duration::from_secs(5);
const UPLOAD_STALL_GRACE: Duration = Duration::from_secs(45);

/// Shared traffic activity tracker updated by [`WatchedStream`] and read by keepalive loops.
#[derive(Debug)]
pub struct ActivityTracker {
    epoch: Instant,
    last_read_ms: AtomicU64,
    last_write_ms: AtomicU64,
    pending_write_start_ms: AtomicU64,
    pending_write_bytes: AtomicUsize,
    pub bytes_rx: AtomicU64,
    pub bytes_tx: AtomicU64,
}

impl Default for ActivityTracker {
    fn default() -> Self {
        Self::new()
    }
}

impl ActivityTracker {
    pub fn new() -> Self {
        Self {
            epoch: Instant::now(),
            last_read_ms: AtomicU64::new(0),
            last_write_ms: AtomicU64::new(0),
            pending_write_start_ms: AtomicU64::new(0),
            pending_write_bytes: AtomicUsize::new(0),
            bytes_rx: AtomicU64::new(0),
            bytes_tx: AtomicU64::new(0),
        }
    }

    fn now_ms(&self) -> u64 {
        self.epoch.elapsed().as_millis() as u64
    }

    pub fn record_read(&self, n: usize) {
        if n > 0 {
            self.last_read_ms.store(self.now_ms(), Ordering::Relaxed);
            self.bytes_rx.fetch_add(n as u64, Ordering::Relaxed);
        }
    }

    pub fn record_write_attempt(&self, len: usize) {
        let now = self.now_ms();
        let prev = self.pending_write_bytes.fetch_add(len, Ordering::Relaxed);
        if prev == 0 {
            self.pending_write_start_ms.store(now, Ordering::Relaxed);
        }
    }

    pub fn record_write_done(&self, attempt_len: usize, written: usize) {
        let _ = self
            .pending_write_bytes
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |cur| {
                Some(cur.saturating_sub(attempt_len))
            });
        if self.pending_write_bytes.load(Ordering::Relaxed) == 0 {
            self.pending_write_start_ms.store(0, Ordering::Relaxed);
        }
        if written > 0 {
            self.last_write_ms.store(self.now_ms(), Ordering::Relaxed);
            self.bytes_tx.fetch_add(written as u64, Ordering::Relaxed);
        }
    }

    /// Returns `true` when recent read activity (<5s) or a queued large upload (<45s)
    /// indicates the connection is healthy and an H2 PING probe should be skipped.
    pub fn should_suppress_ping(&self) -> bool {
        let now = self.now_ms();
        let last_r = self.last_read_ms.load(Ordering::Relaxed);
        if last_r > 0 && now.saturating_sub(last_r) < READ_RECENT_WINDOW.as_millis() as u64 {
            return true;
        }
        let queued = self.pending_write_bytes.load(Ordering::Relaxed);
        if queued >= UPLOAD_SUPPRESS_THRESHOLD_BYTES {
            let started = self.pending_write_start_ms.load(Ordering::Relaxed);
            if started > 0 && now.saturating_sub(started) < UPLOAD_STALL_GRACE.as_millis() as u64 {
                return true;
            }
        }
        false
    }

    /// Snapshots cumulative `(rx_bytes, tx_bytes)`.
    pub fn totals(&self) -> (u64, u64) {
        (
            self.bytes_rx.load(Ordering::Relaxed),
            self.bytes_tx.load(Ordering::Relaxed),
        )
    }
}

/// Wraps an underlying transport stream (`TcpStream` / `BoxedTlsStream`) to feed [`ActivityTracker`].
pub struct WatchedStream<S> {
    inner: S,
    tracker: Arc<ActivityTracker>,
}

impl<S> WatchedStream<S> {
    pub fn new(inner: S, tracker: Arc<ActivityTracker>) -> Self {
        Self { inner, tracker }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for WatchedStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let before = buf.filled().len();
        let poll = Pin::new(&mut self.inner).poll_read(cx, buf);
        if let Poll::Ready(Ok(())) = poll {
            let added = buf.filled().len().saturating_sub(before);
            self.tracker.record_read(added);
        }
        poll
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for WatchedStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.tracker.record_write_attempt(buf.len());
        let poll = Pin::new(&mut self.inner).poll_write(cx, buf);
        match &poll {
            Poll::Ready(Ok(n)) => self.tracker.record_write_done(buf.len(), *n),
            Poll::Ready(Err(_)) | Poll::Pending => self.tracker.record_write_done(buf.len(), 0),
        }
        poll
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}
