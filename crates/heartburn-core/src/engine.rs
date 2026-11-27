//! Public async lifecycle facade [`HeartburnEngine`] for Tauri, Android FFI, and CLI hosts.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use tokio::net::TcpListener;
use tokio::sync::{Mutex, RwLock, broadcast, watch};
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;

use crate::accounts::{AccountCredentials, AccountManager, AccountSlot};
use crate::config::Config;
use crate::controlplane::ControlPlaneClient;
use crate::dialer::{ProtectedDialer, SocketProtector, UpstreamSocks5};
use crate::dns::BootstrapResolver;
use crate::error::{FxaError, HeartburnError, StorageError};
use crate::fxa::{FxaClient, SignInStep};
use crate::guardian::{GuardianClient, ProxyUsage, unix_now};
use crate::inbound::{InboundAuth, TunnelOpener, serve_inbound};
use crate::proxy::controller::{ControllerOpener, ProxyController};
use crate::proxy::status::{EngineEvent, EngineState, EngineStatus};
use crate::serverlist::ServerListManager;
use crate::storage::{FsStorage, Storage};
use crate::tls::{AdaptiveTlsConnector, TlsConnector};

/// Embeddable, storage-agnostic core engine exposing clean async start/stop lifecycle,
/// FXA onboarding/account APIs, status polling/subscriptions, and Android FD protection.
#[derive(Debug)]
pub struct HeartburnEngine {
    storage: Arc<dyn Storage>,
    #[allow(dead_code)]
    dialer: ProtectedDialer,
    config: Arc<RwLock<Config>>,
    controller: Arc<ProxyController>,
    fxa: FxaClient,
    accounts: Arc<AccountManager>,

    status_tx: watch::Sender<EngineStatus>,
    events_tx: broadcast::Sender<EngineEvent>,

    lifecycle_lock: Mutex<()>,
    run_cancel: Mutex<Option<CancellationToken>>,
    run_tasks: Mutex<TaskTracker>,
    bound_listen_addr: RwLock<Option<SocketAddr>>,
}

impl HeartburnEngine {
    /// Opens an engine backed by [`FsStorage`] at caller-provided `data_dir`.
    pub async fn with_data_dir(
        data_dir: impl Into<PathBuf>,
        protector: Option<Arc<dyn SocketProtector>>,
    ) -> Result<Arc<Self>, HeartburnError> {
        let storage: Arc<dyn Storage> = Arc::new(FsStorage::new(data_dir));
        Self::open(storage, protector).await
    }

    /// Initializes the engine over any custom [`Storage`] backend and optional [`SocketProtector`].
    pub async fn open(
        storage: Arc<dyn Storage>,
        protector: Option<Arc<dyn SocketProtector>>,
    ) -> Result<Arc<Self>, HeartburnError> {
        Box::pin(async move {
            let (cfg, _created) = Config::load_from(storage.as_ref()).await?;
            let dialer = ProtectedDialer::with_protector(protector);
            let tls = Arc::new(AdaptiveTlsConnector::new()?);
            let tls_dyn: Arc<dyn TlsConnector> = tls.clone();

            let up_socks = if !cfg.network.upstream_proxy_in_use().is_empty() {
                Some(UpstreamSocks5 {
                    addr: cfg.network.upstream_proxy.clone(),
                    username: cfg.network.upstream_proxy_username.clone(),
                    password: cfg.network.upstream_proxy_password.clone(),
                })
            } else {
                None
            };

            let resolver = Arc::new(BootstrapResolver::new(
                &cfg.dns.servers,
                cfg.dns.fallback_to_system,
                dialer.clone(),
                tls_dyn,
                up_socks,
            )?);
            let resolver_lock = Arc::new(RwLock::new(Arc::clone(&resolver)));

            let control = ControlPlaneClient::new(
                Arc::clone(&resolver),
                dialer.clone(),
                tls.clone() as Arc<dyn TlsConnector>,
                cfg.network.clone(),
            );
            let fxa = FxaClient::new(control.clone());
            let guardian = Arc::new(RwLock::new(GuardianClient::new(
                &cfg.network.guardian_endpoint,
                control.clone(),
                cfg.network.clone(),
                Arc::clone(&storage),
            )));
            let serverlist = ServerListManager::new(control.clone(), Arc::clone(&storage));
            let accounts = Arc::new(
                AccountManager::load(
                    Arc::clone(&storage),
                    &cfg.accounts.order,
                    cfg.accounts.switch_threshold_percent,
                )
                .await?,
            );

            let init_status = EngineStatus {
                state: EngineState::Stopped,
                listen_addr: cfg.proxy.listen.clone(),
                transport: cfg.proxy.transport.clone(),
                updated_at_unix: unix_now(),
                ..Default::default()
            };
            let (status_tx, _) = watch::channel(init_status);
            let (events_tx, _) = broadcast::channel(128);

            let config_lock = Arc::new(RwLock::new(cfg));
            let controller = Arc::new(ProxyController::new(
                Arc::clone(&config_lock),
                Arc::clone(&storage),
                dialer.clone(),
                tls,
                resolver_lock,
                control,
                fxa.clone(),
                guardian,
                serverlist,
                Arc::clone(&accounts),
                status_tx.clone(),
                events_tx.clone(),
                CancellationToken::new(),
            ));

            Ok(Arc::new(Self {
                storage,
                dialer,
                config: config_lock,
                controller,
                fxa,
                accounts,
                status_tx,
                events_tx,
                lifecycle_lock: Mutex::new(()),
                run_cancel: Mutex::new(None),
                run_tasks: Mutex::new(TaskTracker::new()),
                bound_listen_addr: RwLock::new(None),
            }))
        })
        .await
    }

    /// Starts the local loopback inbound SOCKS5/HTTP listener and connects upstream.
    ///
    /// Returns cleanly once upstream is authenticated and listening on `proxy.listen`.
    pub async fn start(&self) -> Result<(), HeartburnError> {
        Box::pin(async move {
            let _guard = self.lifecycle_lock.lock().await;
            if self.run_cancel.lock().await.is_some() {
                return Err(HeartburnError::AlreadyRunning);
            }

            let cfg = self.config.read().await.clone();
            cfg.validate()?;

            let listener = TcpListener::bind(&cfg.proxy.listen)
                .await
                .map_err(|e| HeartburnError::Proxy(crate::error::ProxyError::Io(e)))?;
            let local_addr = listener
                .local_addr()
                .map_err(|e| HeartburnError::Proxy(crate::error::ProxyError::Io(e)))?;
            *self.bound_listen_addr.write().await = Some(local_addr);

            let cancel = CancellationToken::new();
            let tracker = TaskTracker::new();

            let opener: Arc<dyn TunnelOpener> = Arc::new(ControllerOpener(Arc::clone(&self.controller)));
            let auth = Arc::new(InboundAuth {
                username: cfg.proxy.username.clone(),
                password: cfg.proxy.password.clone(),
            });
            let active_tunnels = self.controller.active_tunnels_counter();
            let max_conns = cfg.proxy.max_connections;
            let verbose = cfg.logging.verbose;
            let listener_cancel = cancel.clone();

            tracker.spawn(async move {
                serve_inbound(
                    listener,
                    opener,
                    auth,
                    max_conns,
                    verbose,
                    active_tunnels,
                    listener_cancel,
                )
                .await;
            });

            tracker.close();
            *self.run_cancel.lock().await = Some(cancel);
            *self.run_tasks.lock().await = tracker;

            if let Err(err) = self.controller.connect(None).await {
                self.stop_locked().await;
                return Err(err);
            }

            Ok(())
        })
        .await
    }

    /// Gracefully stops the inbound listener, closes all upstream sessions, and waits
    /// until every background task exits.
    pub async fn stop(&self) -> Result<(), HeartburnError> {
        let _guard = self.lifecycle_lock.lock().await;
        if self.run_cancel.lock().await.is_none() {
            return Err(HeartburnError::NotRunning);
        }
        self.stop_locked().await;
        Ok(())
    }

    async fn stop_locked(&self) {
        if let Some(cancel) = self.run_cancel.lock().await.take() {
            cancel.cancel();
        }
        self.controller.shutdown().await;
        let tracker = std::mem::take(&mut *self.run_tasks.lock().await);
        tracker.close();
        tracker.wait().await;
        *self.bound_listen_addr.write().await = None;
    }

    /// Returns `true` while the inbound proxy listener is running.
    pub async fn is_running(&self) -> bool {
        self.run_cancel.lock().await.is_some()
    }

    /// Returns the actual bound local socket address (useful when `proxy.listen` used port `:0`).
    pub async fn local_listen_addr(&self) -> Option<SocketAddr> {
        *self.bound_listen_addr.read().await
    }

    /// Snapshots current runtime status.
    pub fn status(&self) -> EngineStatus {
        self.status_tx.borrow().clone()
    }

    /// Subscribes to live status updates.
    pub fn subscribe_status(&self) -> watch::Receiver<EngineStatus> {
        self.status_tx.subscribe()
    }

    /// Subscribes to asynchronous lifecycle/quota/failover/log events.
    pub fn subscribe_events(&self) -> broadcast::Receiver<EngineEvent> {
        self.events_tx.subscribe()
    }

    /// Returns current configuration snapshot.
    pub async fn config(&self) -> Config {
        self.config.read().await.clone()
    }

    /// Updates, validates, persists, and hot-reloads updated configuration.
    pub async fn update_config(&self, mut new_cfg: Config) -> Result<(), HeartburnError> {
        Box::pin(async move {
            new_cfg.normalize();
            new_cfg.validate()?;
            new_cfg.save_to(self.storage.as_ref()).await?;
            if self.is_running().await {
                self.controller.reload_config(new_cfg).await?;
            } else {
                *self.config.write().await = new_cfg;
            }
            Ok(())
        })
        .await
    }

    /// Notifies the engine of an OS network change (e.g., Wi-Fi <-> Cellular on Android).
    pub async fn network_changed(&self) -> Result<(), HeartburnError> {
        Box::pin(self.controller.on_network_changed()).await
    }

    /// Triggers an exit IP check through the active Mozilla proxy tunnel.
    pub async fn verify_exit(&self) -> Result<String, HeartburnError> {
        Ok(Box::pin(self.controller.verify_exit()).await?)
    }

    /// Forces switching/reconnecting, optionally targeting a specific `account_id`.
    pub async fn switch_account(&self, account_id: Option<String>) -> Result<(), HeartburnError> {
        Box::pin(async move {
            if let Some(id) = account_id {
                self.controller.connect(Some(id)).await
            } else {
                self.controller
                    .switch_or_reconnect(Some("user requested switch".into()))
                    .await
            }
        })
        .await
    }

    // -----------------------------------------------------------------------
    // Account onboarding & management helpers
    // -----------------------------------------------------------------------

    /// Lists configured account slots (without decrypted passwords).
    pub async fn list_accounts(&self) -> Vec<AccountSlot> {
        self.accounts.list().await
    }

    /// Removes a stored account by ID.
    pub async fn remove_account(&self, id: &str) -> Result<bool, StorageError> {
        self.accounts.remove_account(id).await
    }

    /// Initiates FxA email/password login.
    pub async fn login_fxa(
        &self,
        email: &str,
        password: &str,
        unblock_code: Option<&str>,
    ) -> Result<SignInStep, FxaError> {
        Box::pin(self.fxa.login(email, password, unblock_code)).await
    }

    pub fn fxa_client(&self) -> &FxaClient {
        &self.fxa
    }

    /// Installs or clears the interactive CAPTCHA solver used during FxA logins/verification/OAuth.
    pub fn set_captcha_solver(&self, solver: Option<std::sync::Arc<dyn crate::challenge::CaptchaSolver>>) {
        self.fxa.set_captcha_solver(solver);
    }

    /// Completes onboarding for a verified FxA login response: registers desktop VPN
    /// device, obtains offline OAuth tokens, encrypts password, and saves to `AccountManager`.
    pub async fn complete_account_onboarding(
        &self,
        email: &str,
        password: &str,
        uid: &str,
        session_token: &str,
    ) -> Result<AccountCredentials, HeartburnError> {
        Box::pin(async move {
            let device_id = self
                .fxa
                .register_device(session_token)
                .await
                .unwrap_or_default();
            let oauth = self.fxa.exchange_session_for_oauth(session_token).await?;
            let enc_pw = self.accounts.store().encrypt_password(password).await?;

            let creds = AccountCredentials {
                id: uid.to_owned(),
                email: crate::fxa::normalize_email(email),
                encrypted_password: enc_pw,
                session_token: session_token.to_owned(),
                refresh_token: oauth.refresh_token.unwrap_or_default(),
                access_token: oauth.access_token,
                access_expires_at: unix_now().saturating_add(oauth.expires_in),
                device_id,
            };
            self.accounts.upsert_account(creds.clone()).await?;
            Ok(creds)
        })
        .await
    }

    /// Queries Guardian `HEAD /api/v1/fpn/status` for an account's live quota.
    pub async fn check_account_quota(&self, account_id: &str) -> Result<ProxyUsage, HeartburnError> {
        let _ = self.controller.probe_account_quota(account_id).await?;
        self.accounts
            .list()
            .await
            .into_iter()
            .find(|s| s.creds.id == account_id)
            .and_then(|s| s.usage)
            .ok_or(HeartburnError::Proxy(crate::error::ProxyError::NoAccounts))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::MemoryStorage;

    #[tokio::test]
    async fn engine_opens_validates_config_and_rejects_stop_when_stopped() {
        let storage = Arc::new(MemoryStorage::new());
        let engine = HeartburnEngine::open(storage, None).await.unwrap();
        assert!(!engine.is_running().await);
        assert_eq!(engine.status().state, EngineState::Stopped);

        let mut cfg = engine.config().await;
        cfg.proxy.listen = "127.0.0.1:10811".into();
        engine.update_config(cfg).await.unwrap();
        assert_eq!(engine.config().await.proxy.listen, "127.0.0.1:10811");

        let mut port_zero = engine.config().await;
        port_zero.proxy.listen = "127.0.0.1:0".into();
        assert!(engine.update_config(port_zero).await.is_err());

        let mut bad_cfg = engine.config().await;
        bad_cfg.proxy.transport = "invalid".into();
        assert!(engine.update_config(bad_cfg).await.is_err());

        assert!(matches!(engine.stop().await, Err(HeartburnError::NotRunning)));
    }
}
