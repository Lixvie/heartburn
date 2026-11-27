//! Thin UniFFI bindings wrapping `heartburn-core` for Kotlin on Android
//! (`cdylib` targeting `arm64-v8a` / `armeabi-v7a` via `cargo-ndk`).

use std::fmt;
use std::io;
use std::sync::{Arc, Mutex};

use heartburn_core::config::Config;
use heartburn_core::dialer::{SocketFd, SocketProtector};
use heartburn_core::error::HeartburnError;
use heartburn_core::fxa::SignInStep;
use heartburn_core::{EngineEvent, EngineState, EngineStatus, HeartburnEngine};
use tokio::runtime::Runtime;

uniffi::setup_scaffolding!();

/// Error type exported over UniFFI to Kotlin.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, uniffi::Error)]
pub enum FfiError {
    #[error("{msg}")]
    Config { msg: String },
    #[error("{msg}")]
    Auth { msg: String },
    #[error("{msg}")]
    Proxy { msg: String },
    #[error("engine is already running")]
    AlreadyRunning,
    #[error("engine is not running")]
    NotRunning,
    #[error("{msg}")]
    Internal { msg: String },
}

impl From<HeartburnError> for FfiError {
    fn from(err: HeartburnError) -> Self {
        match err {
            HeartburnError::Config(e) => Self::Config { msg: e.to_string() },
            HeartburnError::Fxa(e) => Self::Auth { msg: e.to_string() },
            HeartburnError::Guardian(e) => Self::Auth { msg: e.to_string() },
            HeartburnError::Proxy(e) => Self::Proxy { msg: e.to_string() },
            HeartburnError::Dial(e) => Self::Proxy { msg: e.to_string() },
            HeartburnError::Tls(e) => Self::Proxy { msg: e.to_string() },
            HeartburnError::AlreadyRunning => Self::AlreadyRunning,
            HeartburnError::NotRunning => Self::NotRunning,
            other => Self::Internal {
                msg: other.to_string(),
            },
        }
    }
}

/// Kotlin callback interface wrapping Android `VpnService.protect(fd: Int): Boolean`.
///
/// Invoked synchronously on every outbound TCP and UDP socket before `connect()`,
/// `bind()`, or `send()` so VPN engine traffic bypasses the TUN interface.
#[uniffi::export(callback_interface)]
pub trait FfiSocketProtector: Send + Sync {
    /// Protects `fd` and returns `true` when Android `VpnService.protect` succeeded.
    fn protect_fd(&self, fd: i32) -> bool;
}

/// Event observer callback implemented by Kotlin hosts.
#[uniffi::export(callback_interface)]
pub trait FfiEventListener: Send + Sync {
    fn on_event(&self, event: FfiEngineEvent);
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum FfiEngineState {
    Stopped,
    Starting,
    Connecting,
    Connected,
    Sleeping,
    Reconnecting,
    Error,
}

impl From<EngineState> for FfiEngineState {
    fn from(s: EngineState) -> Self {
        match s {
            EngineState::Stopped => Self::Stopped,
            EngineState::Starting => Self::Starting,
            EngineState::Connecting => Self::Connecting,
            EngineState::Connected => Self::Connected,
            EngineState::Sleeping => Self::Sleeping,
            EngineState::Reconnecting => Self::Reconnecting,
            EngineState::Error => Self::Error,
        }
    }
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct FfiEngineStatus {
    pub state: FfiEngineState,
    pub listen_addr: String,
    pub transport: String,
    pub server: String,
    pub country_code: String,
    pub country_name: String,
    pub city: String,
    pub active_account_email: Option<String>,
    pub quota_used_bytes: u64,
    pub quota_limit_bytes: u64,
    pub quota_remaining_bytes: u64,
    pub active_tunnels: u64,
    pub bytes_rx: u64,
    pub bytes_tx: u64,
    pub exit_ip: Option<String>,
    pub last_error: Option<String>,
}

impl From<EngineStatus> for FfiEngineStatus {
    fn from(s: EngineStatus) -> Self {
        let (used, limit, rem) = match s.usage {
            Some(u) => (u.used_bytes, u.limit_bytes, u.remaining_bytes),
            None => (0, 0, 0),
        };
        Self {
            state: s.state.into(),
            listen_addr: s.listen_addr,
            transport: s.transport,
            server: s.server,
            country_code: s.country_code,
            country_name: s.country_name,
            city: s.city,
            active_account_email: s.active_account_email,
            quota_used_bytes: used,
            quota_limit_bytes: limit,
            quota_remaining_bytes: rem,
            active_tunnels: s.active_tunnels as u64,
            bytes_rx: s.bytes_rx,
            bytes_tx: s.bytes_tx,
            exit_ip: s.exit_ip,
            last_error: s.last_error,
        }
    }
}

#[derive(Debug, Clone, uniffi::Enum)]
pub enum FfiEngineEvent {
    StateChanged {
        state: FfiEngineState,
        server: String,
        transport: String,
        account_id: Option<String>,
        error: Option<String>,
    },
    AccountSwitched {
        from_id: Option<String>,
        to_id: String,
        reason: String,
    },
    QuotaUpdated {
        account_id: String,
        used_bytes: u64,
        limit_bytes: u64,
        remaining_bytes: u64,
    },
    ExitVerified {
        exit_ip: String,
    },
    Log {
        level: String,
        message: String,
    },
}

impl From<EngineEvent> for FfiEngineEvent {
    fn from(ev: EngineEvent) -> Self {
        match ev {
            EngineEvent::StateChanged {
                state,
                server,
                transport,
                account_id,
                error,
            } => Self::StateChanged {
                state: state.into(),
                server,
                transport,
                account_id,
                error,
            },
            EngineEvent::AccountSwitched {
                from_id,
                to_id,
                reason,
            } => Self::AccountSwitched {
                from_id,
                to_id,
                reason,
            },
            EngineEvent::QuotaUpdated { account_id, usage } => Self::QuotaUpdated {
                account_id,
                used_bytes: usage.used_bytes,
                limit_bytes: usage.limit_bytes,
                remaining_bytes: usage.remaining_bytes,
            },
            EngineEvent::ExitVerified { exit_ip } => Self::ExitVerified { exit_ip },
            EngineEvent::Log { level, message } => Self::Log { level, message },
        }
    }
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct FfiAccountSummary {
    pub id: String,
    pub email: String,
    pub enabled: bool,
    pub exhausted: bool,
    pub quota_percent: f64,
}

#[derive(Debug, Clone, uniffi::Record)]
pub struct FfiSignInResult {
    pub verified: bool,
    pub uid: String,
    pub session_token: String,
    pub verification_method: Option<String>,
    pub email: String,
}

struct ProtectorBridge(Box<dyn FfiSocketProtector>);

impl fmt::Debug for ProtectorBridge {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ProtectorBridge").finish()
    }
}

impl SocketProtector for ProtectorBridge {
    #[allow(clippy::unnecessary_cast)]
    fn protect_fd(&self, fd: SocketFd) -> io::Result<()> {
        if self.0.protect_fd(fd as i32) {
            Ok(())
        } else {
            Err(io::Error::other(
                "Android VpnService.protect(fd) returned false",
            ))
        }
    }
}

/// UniFFI wrapper exposing [`HeartburnEngine`] to Android Kotlin hosts.
#[derive(uniffi::Object)]
pub struct FfiEngine {
    runtime: Arc<Runtime>,
    inner: Arc<HeartburnEngine>,
    listener_handle: Mutex<Option<tokio::task::JoinHandle<()>>>,
}

#[uniffi::export]
impl FfiEngine {
    /// Opens an engine storing `config.json`, encrypted credentials, and caches in `data_dir`.
    ///
    /// Pass Android's `VpnService.protect` wrapper as `protector` to bypass the TUN device.
    #[uniffi::constructor]
    pub fn open(
        data_dir: String,
        protector: Option<Box<dyn FfiSocketProtector>>,
    ) -> Result<Arc<Self>, FfiError> {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .thread_name("heartburn-ffi")
            .build()
            .map_err(|e| FfiError::Internal {
                msg: format!("failed creating tokio runtime: {e}"),
            })?;

        let core_protector: Option<Arc<dyn SocketProtector>> =
            protector.map(|p| Arc::new(ProtectorBridge(p)) as Arc<dyn SocketProtector>);

        let inner = runtime
            .block_on(HeartburnEngine::with_data_dir(data_dir, core_protector))
            .map_err(FfiError::from)?;

        Ok(Arc::new(Self {
            runtime: Arc::new(runtime),
            inner,
            listener_handle: Mutex::new(None),
        }))
    }

    pub fn start(&self) -> Result<(), FfiError> {
        self.runtime
            .block_on(self.inner.start())
            .map_err(FfiError::from)
    }

    pub fn stop(&self) -> Result<(), FfiError> {
        self.runtime
            .block_on(self.inner.stop())
            .map_err(FfiError::from)
    }

    pub fn is_running(&self) -> bool {
        self.runtime.block_on(self.inner.is_running())
    }

    pub fn status(&self) -> FfiEngineStatus {
        self.inner.status().into()
    }

    pub fn network_changed(&self) -> Result<(), FfiError> {
        self.runtime
            .block_on(self.inner.network_changed())
            .map_err(FfiError::from)
    }

    pub fn verify_exit(&self) -> Result<String, FfiError> {
        self.runtime
            .block_on(self.inner.verify_exit())
            .map_err(FfiError::from)
    }

    pub fn switch_account(&self, account_id: Option<String>) -> Result<(), FfiError> {
        self.runtime
            .block_on(self.inner.switch_account(account_id))
            .map_err(FfiError::from)
    }

    pub fn get_config_json(&self) -> Result<String, FfiError> {
        let cfg = self.runtime.block_on(self.inner.config());
        serde_json::to_string_pretty(&cfg).map_err(|e| FfiError::Config { msg: e.to_string() })
    }

    pub fn set_config_json(&self, json: String) -> Result<(), FfiError> {
        let cfg: Config =
            serde_json::from_str(&json).map_err(|e| FfiError::Config { msg: e.to_string() })?;
        self.runtime
            .block_on(self.inner.update_config(cfg))
            .map_err(FfiError::from)
    }

    pub fn list_accounts(&self) -> Vec<FfiAccountSummary> {
        self.runtime
            .block_on(self.inner.list_accounts())
            .into_iter()
            .map(|s| FfiAccountSummary {
                id: s.creds.id,
                email: s.creds.email,
                enabled: s.enabled,
                exhausted: s.exhausted,
                quota_percent: s.usage.map(|u| u.used_percent()).unwrap_or(0.0),
            })
            .collect()
    }

    pub fn remove_account(&self, account_id: String) -> Result<bool, FfiError> {
        self.runtime
            .block_on(self.inner.remove_account(&account_id))
            .map_err(|e| FfiError::Internal { msg: e.to_string() })
    }

    pub fn login_fxa(
        &self,
        email: String,
        password: String,
        unblock_code: Option<String>,
    ) -> Result<FfiSignInResult, FfiError> {
        let step = self
            .runtime
            .block_on(self.inner.login_fxa(&email, &password, unblock_code.as_deref()))
            .map_err(|e| FfiError::Auth { msg: e.to_string() })?;
        match step {
            SignInStep::Verified(s) => Ok(FfiSignInResult {
                verified: true,
                uid: s.uid,
                session_token: s.session_token,
                verification_method: None,
                email,
            }),
            SignInStep::NeedsVerification { session, method } => Ok(FfiSignInResult {
                verified: false,
                uid: session.uid,
                session_token: session.session_token,
                verification_method: Some(method),
                email,
            }),
        }
    }

    pub fn verify_email_code(&self, session_token: String, code: String) -> Result<(), FfiError> {
        self.runtime
            .block_on(self.inner.fxa_client().verify_email_code(&session_token, &code))
            .map_err(|e| FfiError::Auth { msg: e.to_string() })
    }

    pub fn verify_totp(&self, session_token: String, code: String) -> Result<bool, FfiError> {
        self.runtime
            .block_on(self.inner.fxa_client().verify_totp(&session_token, &code))
            .map_err(|e| FfiError::Auth { msg: e.to_string() })
    }

    pub fn complete_account_onboarding(
        &self,
        email: String,
        password: String,
        uid: String,
        session_token: String,
    ) -> Result<FfiAccountSummary, FfiError> {
        let creds = self
            .runtime
            .block_on(self.inner.complete_account_onboarding(
                &email,
                &password,
                &uid,
                &session_token,
            ))
            .map_err(FfiError::from)?;
        Ok(FfiAccountSummary {
            id: creds.id,
            email: creds.email,
            enabled: true,
            exhausted: false,
            quota_percent: 0.0,
        })
    }

    /// Registers a Kotlin event listener receiving live [`FfiEngineEvent`] notifications.
    pub fn set_event_listener(&self, listener: Option<Box<dyn FfiEventListener>>) {
        let mut guard = match self.listener_handle.lock() {
            Ok(g) => g,
            Err(_) => return,
        };
        if let Some(prev) = guard.take() {
            prev.abort();
        }
        let Some(cb) = listener else {
            return;
        };
        let mut rx = self.inner.subscribe_events();
        let handle = self.runtime.spawn(async move {
            while let Ok(ev) = rx.recv().await {
                cb.on_event(ev.into());
            }
        });
        *guard = Some(handle);
    }
}

impl Drop for FfiEngine {
    fn drop(&mut self) {
        if let Ok(mut guard) = self.listener_handle.lock()
            && let Some(h) = guard.take()
        {
            h.abort();
        }
        if self.runtime.block_on(self.inner.is_running()) {
            let _ = self.runtime.block_on(self.inner.stop());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};

    struct TestProtector(Arc<AtomicBool>);

    impl FfiSocketProtector for TestProtector {
        fn protect_fd(&self, fd: i32) -> bool {
            assert!(fd >= 0);
            self.0.store(true, Ordering::SeqCst);
            true
        }
    }

    #[test]
    fn ffi_engine_opens_and_reads_config_and_status() {
        let dir = std::env::temp_dir().join(format!(
            "heartburn-ffi-test-{}",
            std::process::id() ^ 0x55aa
        ));
        let called = Arc::new(AtomicBool::new(false));
        let protector: Box<dyn FfiSocketProtector> = Box::new(TestProtector(Arc::clone(&called)));

        let engine = FfiEngine::open(dir.display().to_string(), Some(protector)).unwrap();
        assert!(!engine.is_running());
        assert_eq!(engine.status().state, FfiEngineState::Stopped);
        let cfg_json = engine.get_config_json().unwrap();
        assert!(cfg_json.contains("127.0.0.1:10810"));
        assert!(engine.list_accounts().is_empty());

        let _ = std::fs::remove_dir_all(&dir);
    }
}
