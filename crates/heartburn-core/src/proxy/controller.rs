//! Upstream connection controller, automatic ProxyPass renewal, quota failover,
//! idle sleep/wake, exit verification, and standby server failover (`proxy/controller.go`, `renewal.go`).

use std::collections::HashSet;
use std::future::Future;
use std::net::IpAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{Mutex, RwLock, broadcast, watch};
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;

use crate::accounts::{AccountManager, AccountSlot};
use crate::config::{Config, EXIT_CHECK_TIMEOUT, IpVersionMode, TransportKind};
use crate::controlplane::{ControlPlaneClient, TunnelDialFn};
use crate::dialer::{ProtectedDialer, UpstreamSocks5};
use crate::dns::BootstrapResolver;
use crate::error::{GuardianError, HeartburnError, ProxyError};
use crate::fxa::FxaClient;
use crate::guardian::{GuardianClient, ProxyPassInfo, unix_now};
use crate::hellosplit::HelloSplitMode;
use crate::inbound::TunnelOpener;
use crate::proxy::failover::{FailureKind, ServerFailover, classify_upstream_error};
use crate::proxy::pool::SessionPool;
use crate::proxy::status::{EngineEvent, EngineState, EngineStatus};
use crate::proxy::upstream_h1::H1Session;
use crate::proxy::upstream_h2::H2Session;
use crate::proxy::upstream_h3::{H3_FALLBACK_HANDSHAKE_TIMEOUT, H3Session};
use crate::proxy::{UdpTunnel, UpstreamSession};
use crate::serverlist::{JexlEnv, ProxyCandidate, SelectionCache, ServerListManager, select_candidates};
use crate::storage::Storage;
use crate::tls::{AdaptiveTlsConnector, BoxStream, TlsConfig, TlsConnector, TlsFingerprint};

const PROXY_PASS_RENEW_LEAD: Duration = Duration::from_secs(2 * 60);
const PASS_RENEW_TIMEOUT: Duration = Duration::from_secs(2 * 60);
const MIN_RENEWAL_INTERVAL: Duration = Duration::from_secs(10);
const QUOTA_POLL_INTERVAL: Duration = Duration::from_secs(5 * 60);
const USAGE_PROBE_BYTES: u64 = 512 * 1024 * 1024;
const QUOTA_PROBE_MARGIN: u64 = 5 * 1024 * 1024 * 1024;
const IDLE_CHECK_INTERVAL: Duration = Duration::from_secs(15);
const ACCOUNT_ERROR_COOLDOWN: Duration = Duration::from_secs(60);
const MAX_FASTEST_PROBES: usize = 6;

/// Coordinates upstream sessions, accounts, renewals, and failover for [`HeartburnEngine`].
pub struct ProxyController {
    config: Arc<RwLock<Config>>,
    storage: Arc<dyn Storage>,
    dialer: ProtectedDialer,
    tls: Arc<AdaptiveTlsConnector>,
    resolver: Arc<RwLock<Arc<BootstrapResolver>>>,
    control: ControlPlaneClient,
    fxa: FxaClient,
    guardian: Arc<RwLock<GuardianClient>>,
    serverlist: ServerListManager,
    accounts: Arc<AccountManager>,
    failover: Arc<ServerFailover>,

    pool: Arc<RwLock<Option<Arc<SessionPool>>>>,
    active_server: Arc<RwLock<Option<ProxyCandidate>>>,
    active_transport: Arc<RwLock<Option<TransportKind>>>,
    cached_candidates: Arc<RwLock<Vec<ProxyCandidate>>>,

    connect_lock: Mutex<()>,
    active_tunnels: Arc<AtomicUsize>,
    epoch: Instant,
    last_activity_ms: AtomicU64,
    sleeping: AtomicBool,
    last_error: Arc<RwLock<Option<String>>>,
    exit_ip: Arc<RwLock<Option<String>>>,
    bytes_rx: AtomicU64,
    bytes_tx: AtomicU64,
    last_probe_total_bytes: AtomicU64,

    status_tx: watch::Sender<EngineStatus>,
    events_tx: broadcast::Sender<EngineEvent>,

    root_cancel: CancellationToken,
    session_cancel: Mutex<CancellationToken>,
    session_tasks: Mutex<TaskTracker>,
}

impl std::fmt::Debug for ProxyController {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProxyController").finish()
    }
}

impl ProxyController {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        config: Arc<RwLock<Config>>,
        storage: Arc<dyn Storage>,
        dialer: ProtectedDialer,
        tls: Arc<AdaptiveTlsConnector>,
        resolver: Arc<RwLock<Arc<BootstrapResolver>>>,
        control: ControlPlaneClient,
        fxa: FxaClient,
        guardian: Arc<RwLock<GuardianClient>>,
        serverlist: ServerListManager,
        accounts: Arc<AccountManager>,
        status_tx: watch::Sender<EngineStatus>,
        events_tx: broadcast::Sender<EngineEvent>,
        root_cancel: CancellationToken,
    ) -> Self {
        Self {
            config,
            storage,
            dialer,
            tls,
            resolver,
            control,
            fxa,
            guardian,
            serverlist,
            accounts,
            failover: Arc::new(ServerFailover::new()),
            pool: Arc::new(RwLock::new(None)),
            active_server: Arc::new(RwLock::new(None)),
            active_transport: Arc::new(RwLock::new(None)),
            cached_candidates: Arc::new(RwLock::new(Vec::new())),
            connect_lock: Mutex::new(()),
            active_tunnels: Arc::new(AtomicUsize::new(0)),
            epoch: Instant::now(),
            last_activity_ms: AtomicU64::new(0),
            sleeping: AtomicBool::new(false),
            last_error: Arc::new(RwLock::new(None)),
            exit_ip: Arc::new(RwLock::new(None)),
            bytes_rx: AtomicU64::new(0),
            bytes_tx: AtomicU64::new(0),
            last_probe_total_bytes: AtomicU64::new(0),
            status_tx,
            events_tx,
            root_cancel,
            session_cancel: Mutex::new(CancellationToken::new()),
            session_tasks: Mutex::new(TaskTracker::new()),
        }
    }

    pub fn active_tunnels_counter(&self) -> Arc<AtomicUsize> {
        Arc::clone(&self.active_tunnels)
    }

    /// Touches idle activity timestamp (called whenever client streams open/close).
    pub fn note_activity(&self) {
        self.last_activity_ms
            .store(self.epoch.elapsed().as_millis() as u64, Ordering::Relaxed);
    }

    /// Establishes (or rebuilds) the active upstream proxy session pool.
    pub async fn connect(self: &Arc<Self>, preferred_account: Option<String>) -> Result<(), HeartburnError> {
        let _guard = self.connect_lock.lock().await;
        self.connect_locked(preferred_account.as_deref(), false).await
    }

    /// Ensures the engine is awake and connected before opening a client tunnel.
    pub async fn ensure_connected(self: &Arc<Self>) -> Result<Arc<SessionPool>, ProxyError> {
        if !self.sleeping.load(Ordering::Relaxed)
            && let Some(ref pool) = *self.pool.read().await
            && !pool.all_closed()
        {
            return Ok(Arc::clone(pool));
        }
        let _guard = self.connect_lock.lock().await;
        if !self.sleeping.load(Ordering::Relaxed)
            && let Some(ref pool) = *self.pool.read().await
            && !pool.all_closed()
        {
            return Ok(Arc::clone(pool));
        }
        self.connect_locked(None, false)
            .await
            .map_err(|e| ProxyError::Transport(e.to_string()))?;
        self.pool
            .read()
            .await
            .clone()
            .ok_or_else(|| ProxyError::Transport("controller pool unavailable after connect".into()))
    }

    fn connect_locked<'a>(
        self: &'a Arc<Self>,
        preferred_account: Option<&'a str>,
        allow_failover_standins: bool,
    ) -> Pin<Box<dyn Future<Output = Result<(), HeartburnError>> + Send + 'a>> {
        Box::pin(async move {
        self.stop_session_loops().await;
        self.sleeping.store(false, Ordering::Relaxed);
        *self.last_error.write().await = None;
        self.emit_state(EngineState::Connecting, None).await;

        let cfg = self.config.read().await.clone();
        let ua = self.prepare_user_agent().await;

        let (account, pass) = self
            .acquire_account_and_pass(preferred_account)
            .await
            .inspect_err(|e| {
                let msg = e.to_string();
                let _ = self.events_tx.send(EngineEvent::StateChanged {
                    state: EngineState::Error,
                    server: String::new(),
                    transport: cfg.proxy.transport.clone(),
                    account_id: None,
                    error: Some(msg),
                });
            })?;

        let candidates = self
            .resolve_target_candidates(&cfg, &ua, allow_failover_standins)
            .await?;

        let (pool, chosen) = self
            .dial_best_candidate(&cfg, &ua, &pass.token, &candidates)
            .await?;

        *self.pool.write().await = Some(Arc::clone(&pool));
        *self.active_server.write().await = Some(chosen.clone());
        *self.active_transport.write().await = Some(pool.transport());
        self.accounts.set_active(&account.creds.id).await;
        self.note_activity();

        // Install renewal tunnel dialer so control-plane calls can traverse Mozilla if direct blocks.
        let dial_fn = self.make_tunnel_dialer(Arc::clone(&pool));
        self.control.set_tunnel_dialer(Some(dial_fn)).await;

        self.serverlist
            .save_selection(&SelectionCache {
                server: chosen.addr(),
                country_code: chosen.country_code.clone(),
                country_name: chosen.country_name.clone(),
                city: chosen.city.clone(),
                selected_at_unix: unix_now(),
            })
            .await;

        self.emit_state(EngineState::Connected, None).await;
        self.start_session_loops(pass, account.creds.id.clone()).await;

        // Asynchronous exit IP verification (non-blocking).
        let me = Arc::clone(self);
        tokio::spawn(async move {
            let _ = me.verify_exit().await;
        });

        Ok(())
        })
    }

    async fn prepare_user_agent(&self) -> String {
        let ver = self.serverlist.fetch_firefox_version().await;
        let major = ver.split('.').next().unwrap_or("158").to_owned();
        self.control.set_firefox_major_version(&major).await;
        self.control.user_agent().await
    }

    async fn acquire_account_and_pass(
        &self,
        preferred_id: Option<&str>,
    ) -> Result<(AccountSlot, ProxyPassInfo), HeartburnError> {
        let mut tried = HashSet::new();
        let mut last_err: Option<HeartburnError> = None;

        while let Some(slot) = self.accounts.select_candidate(preferred_id).await {
            if !tried.insert(slot.creds.id.clone()) {
                break;
            }
            match self.ensure_pass_for_account(&slot).await {
                Ok(pass) => return Ok((slot, pass)),
                Err(err) => {
                    tracing::warn!(account_id = %slot.creds.id, error = %err, "account ProxyPass fetch failed");
                    self.accounts
                        .mark_error(&slot.creds.id, err.to_string(), ACCOUNT_ERROR_COOLDOWN)
                        .await;
                    last_err = Some(err);
                }
            }
        }

        if let Some(e) = last_err {
            Err(e)
        } else if self.accounts.list().await.is_empty() {
            Err(HeartburnError::Proxy(ProxyError::NoAccounts))
        } else {
            Err(HeartburnError::Proxy(ProxyError::AllAccountsExhausted))
        }
    }

    async fn ensure_pass_for_account(
        &self,
        slot: &AccountSlot,
    ) -> Result<ProxyPassInfo, HeartburnError> {
        // Check cached pass if > 2m lifetime remains.
        if let Some(ref cached) = slot.proxy_pass
            && cached.remaining() > PROXY_PASS_RENEW_LEAD + Duration::from_secs(15)
        {
            return Ok(cached.clone());
        }

        let mut access_token = slot.creds.access_token.clone();
        let mut current_refresh = slot.creds.refresh_token.clone();
        let token_exp = slot.creds.access_expires_at;
        let need_refresh = access_token.is_empty()
            || (token_exp > 0 && token_exp <= unix_now().saturating_add(120));

        if need_refresh && !current_refresh.is_empty() {
            match self.fxa.refresh_oauth_token(&current_refresh).await {
                Ok(tok) => {
                    access_token = tok.access_token.clone();
                    if let Some(ref next_rt) = tok.refresh_token
                        && !next_rt.is_empty()
                    {
                        current_refresh = next_rt.clone();
                    }
                    let _ = self
                        .accounts
                        .update_oauth_tokens(
                            &slot.creds.id,
                            tok.access_token,
                            tok.refresh_token,
                            tok.expires_in,
                        )
                        .await;
                }
                Err(e) if access_token.is_empty() => return Err(HeartburnError::Fxa(e)),
                Err(e) => {
                    tracing::debug!(account = %slot.creds.id, error = %e, "OAuth refresh failed; trying existing access token");
                }
            }
        }

        if access_token.is_empty() {
            return Err(HeartburnError::Proxy(ProxyError::AuthFailed));
        }

        let guardian = self.guardian.read().await.clone();
        match guardian.fetch_proxy_pass(&access_token).await {
            Ok(pass) => {
                self.accounts.update_proxy_pass(&slot.creds.id, pass.clone()).await;
                Ok(pass)
            }
            Err(GuardianError::Unauthorized) if !current_refresh.is_empty() => {
                let tok = self.fxa.refresh_oauth_token(&current_refresh).await?;
                access_token = tok.access_token.clone();
                let _ = self
                    .accounts
                    .update_oauth_tokens(
                        &slot.creds.id,
                        tok.access_token,
                        tok.refresh_token,
                        tok.expires_in,
                    )
                    .await;
                match guardian.fetch_proxy_pass(&access_token).await {
                    Ok(pass) => {
                        self.accounts.update_proxy_pass(&slot.creds.id, pass.clone()).await;
                        Ok(pass)
                    }
                    Err(GuardianError::NoSubscription) => {
                        let _ = guardian.activate(&access_token).await;
                        let pass = guardian.fetch_proxy_pass(&access_token).await?;
                        self.accounts.update_proxy_pass(&slot.creds.id, pass.clone()).await;
                        Ok(pass)
                    }
                    Err(e) => Err(HeartburnError::Guardian(e)),
                }
            }
            Err(GuardianError::NoSubscription) => {
                // Attempt entitlement activation once cleanly.
                let _ = guardian.activate(&access_token).await;
                let pass = guardian.fetch_proxy_pass(&access_token).await?;
                self.accounts.update_proxy_pass(&slot.creds.id, pass.clone()).await;
                Ok(pass)
            }
            Err(e) => Err(HeartburnError::Guardian(e)),
        }
    }

    async fn resolve_target_candidates(
        &self,
        cfg: &Config,
        ua: &str,
        include_failover_standins: bool,
    ) -> Result<Vec<ProxyCandidate>, HeartburnError> {
        let mut env = JexlEnv::default();
        if let Some(ver) = ua.split("Firefox/").nth(1) {
            env.version = ver.to_owned();
        }
        let all = self.serverlist.load_candidates(&env).await?;
        *self.cached_candidates.write().await = all.clone();

        let mut primary = select_candidates(&all, &cfg.proxy.country, &cfg.proxy.server)?;
        if cfg.proxy.country.trim().eq_ignore_ascii_case("fastest") && primary.len() > 1 {
            primary = self.rank_fastest(primary).await;
        }

        let avoid = self.failover.avoided_set();
        primary.retain(|c| !avoid.contains(&c.addr()));

        if include_failover_standins || primary.is_empty() {
            let cur_cc = primary
                .first()
                .map(|c| c.country_code.as_str())
                .unwrap_or(cfg.proxy.country.as_str());
            let standins = self.failover.standin_candidates(&all, cur_cc);
            for s in standins {
                if !primary.iter().any(|p| p.addr() == s.addr()) {
                    primary.push(s);
                }
            }
        }

        if primary.is_empty() {
            // Last resort: lift avoidance cache and use unfiltered selection.
            self.failover.clear();
            primary = select_candidates(&all, &cfg.proxy.country, &cfg.proxy.server)?;
        }
        Ok(primary)
    }

    async fn rank_fastest(&self, mut list: Vec<ProxyCandidate>) -> Vec<ProxyCandidate> {
        let probe_count = list.len().min(MAX_FASTEST_PROBES);
        let resolver = self.resolver.read().await.clone();
        let tls = Arc::clone(&self.tls);
        let ip_ver = self.config.read().await.ip_version_mode().unwrap_or_default();

        let mut futs = Vec::with_capacity(probe_count);
        for (idx, cand) in list.iter().take(probe_count).enumerate() {
            let r = Arc::clone(&resolver);
            let t = Arc::clone(&tls);
            let h = cand.host.clone();
            let p = cand.port;
            futs.push(async move {
                let start = Instant::now();
                let res = async {
                    let (tcp, _) = r.dial_tcp(&h, p, ip_ver, Duration::from_secs(5)).await.ok()?;
                    let cfg = TlsConfig {
                        server_name: h.clone(),
                        alpn: vec![b"h2".to_vec()],
                        ech_config_list: None,
                        tls12_only: false,
                        fingerprint: TlsFingerprint::Firefox158,
                    };
                    t.connect(Box::new(tcp), &cfg).await.ok()?;
                    Some(start.elapsed())
                }
                .await;
                (idx, res.unwrap_or(Duration::from_secs(60)))
            });
        }

        let mut timings = futures::future::join_all(futs).await;
        timings.sort_by_key(|&(_, d)| d);
        let mut ranked: Vec<ProxyCandidate> = timings.into_iter().map(|(i, _)| list[i].clone()).collect();
        for c in list.drain(..).skip(probe_count) {
            ranked.push(c);
        }
        ranked
    }

    async fn dial_best_candidate(
        &self,
        cfg: &Config,
        ua: &str,
        proxy_pass: &str,
        candidates: &[ProxyCandidate],
    ) -> Result<(Arc<SessionPool>, ProxyCandidate), HeartburnError> {
        let mut transport = cfg.transport_kind()?;
        // SOCKS5 upstream proxy carries TCP only; HTTP/3 over QUIC isn't supported over SOCKS5.
        if transport == TransportKind::H3 && !cfg.network.upstream_proxy_in_use().is_empty() {
            tracing::info!("upstream SOCKS5 proxy is enabled; using HTTP/2 instead of HTTP/3");
            transport = TransportKind::H2;
        }
        let split_mode = cfg.hello_split_mode()?;
        let ip_version = cfg.ip_version_mode()?;
        let resolver = self.resolver.read().await.clone();
        let count = cfg.proxy.upstream_connections.max(1);

        let mut last_err: Option<ProxyError> = None;

        for cand in candidates {
            match self
                .dial_candidate_pool(
                    cand,
                    transport,
                    count,
                    ua,
                    proxy_pass,
                    split_mode,
                    ip_version,
                    Arc::clone(&resolver),
                )
                .await
            {
                Ok(pool) => {
                    self.failover.record_success(&cand.addr());
                    return Ok((pool, cand.clone()));
                }
                Err(err) => {
                    tracing::warn!(server = %cand.addr(), error = %err, "candidate session dial failed");
                    self.failover.record_failure(&cand.addr());
                    last_err = Some(err);
                }
            }
        }

        Err(HeartburnError::Proxy(last_err.unwrap_or_else(|| {
            ProxyError::Transport("all proxy server candidates failed".into())
        })))
    }

    #[allow(clippy::too_many_arguments)]
    async fn dial_candidate_pool(
        &self,
        cand: &ProxyCandidate,
        transport: TransportKind,
        count: usize,
        ua: &str,
        pass: &str,
        split_mode: HelloSplitMode,
        ip_version: IpVersionMode,
        resolver: Arc<BootstrapResolver>,
    ) -> Result<Arc<SessionPool>, ProxyError> {
        let tls_dyn: Arc<dyn TlsConnector> = Arc::clone(&self.tls) as Arc<dyn TlsConnector>;
        let mut sessions: Vec<Arc<dyn UpstreamSession>> = Vec::with_capacity(count);
        let mut effective_transport = transport;

        for idx in 0..count {
            let sess: Arc<dyn UpstreamSession> = match effective_transport {
                TransportKind::H2 => H2Session::connect(
                    cand.host.clone(),
                    cand.port,
                    ua.to_owned(),
                    pass.to_owned(),
                    split_mode,
                    ip_version,
                    Arc::clone(&resolver),
                    Arc::clone(&tls_dyn),
                )
                .await?,
                TransportKind::H1 => H1Session::connect(
                    cand.host.clone(),
                    cand.port,
                    ua.to_owned(),
                    pass.to_owned(),
                    split_mode,
                    ip_version,
                    Arc::clone(&resolver),
                    Arc::clone(&tls_dyn),
                )
                .await?,
                TransportKind::H3 => {
                    let handshake_timeout = if idx == 0 {
                        H3_FALLBACK_HANDSHAKE_TIMEOUT
                    } else {
                        crate::config::CONNECT_TIMEOUT
                    };
                    match H3Session::connect_with_timeout(
                        cand.host.clone(),
                        cand.port,
                        ua.to_owned(),
                        pass.to_owned(),
                        ip_version,
                        Arc::clone(&resolver),
                        self.dialer.clone(),
                        self.tls.rustls().clone(),
                        handshake_timeout,
                    )
                    .await
                    {
                        Ok(h3) => h3,
                        Err(h3_err) if idx == 0 => {
                            tracing::warn!(server = %cand.addr(), error = %h3_err, "HTTP/3 failed; falling back to HTTP/2");
                            effective_transport = TransportKind::H2;
                            H2Session::connect(
                                cand.host.clone(),
                                cand.port,
                                ua.to_owned(),
                                pass.to_owned(),
                                split_mode,
                                ip_version,
                                Arc::clone(&resolver),
                                Arc::clone(&tls_dyn),
                            )
                            .await?
                        }
                        Err(h3_err) => return Err(h3_err),
                    }
                }
            };
            sessions.push(sess);
        }

        // Open auxiliary H2 session for CONNECT-UDP when main transport is H3 or H1.
        let udp_aux = if effective_transport != TransportKind::H2 {
            H2Session::connect(
                cand.host.clone(),
                cand.port,
                ua.to_owned(),
                pass.to_owned(),
                split_mode,
                ip_version,
                resolver,
                tls_dyn,
            )
            .await
            .ok()
            .map(|h| h as Arc<dyn UpstreamSession>)
        } else {
            None
        };

        Ok(Arc::new(SessionPool::new(effective_transport, sessions, udp_aux)))
    }

    fn make_tunnel_dialer(&self, pool: Arc<SessionPool>) -> TunnelDialFn {
        Arc::new(move |host: String, port: u16| {
            let p = Arc::clone(&pool);
            Box::pin(async move {
                p.open_tcp(None, &host, port)
                    .await
                    .map_err(|e| std::io::Error::other(e.to_string()))
            })
        })
    }

    async fn start_session_loops(
        self: &Arc<Self>,
        initial_pass: ProxyPassInfo,
        account_id: String,
    ) {
        let mut cancel_guard = self.session_cancel.lock().await;
        let cancel = CancellationToken::new();
        *cancel_guard = cancel.clone();
        drop(cancel_guard);

        let tracker = TaskTracker::new();

        // 1. ProxyPass auto-renewal loop (renews 2m before expiry, min 10s interval).
        {
            let me = Arc::clone(self);
            let c = cancel.clone();
            let mut pass = initial_pass;
            let acc_id = account_id.clone();
            tracker.spawn(async move {
                loop {
                    let wait = pass
                        .remaining()
                        .saturating_sub(PROXY_PASS_RENEW_LEAD)
                        .max(MIN_RENEWAL_INTERVAL);
                    tokio::select! {
                        _ = c.cancelled() => break,
                        _ = tokio::time::sleep(wait) => {}
                    }
                    if me.sleeping.load(Ordering::Relaxed) {
                        break;
                    }
                    match tokio::time::timeout(PASS_RENEW_TIMEOUT, me.renew_proxy_pass(&acc_id)).await {
                        Ok(Ok(new_pass)) => {
                            pass = new_pass;
                        }
                        Ok(Err(e)) => {
                            tracing::warn!(account = %acc_id, error = %e, "background ProxyPass renewal failed; triggering reconnect");
                            let _ = me.switch_or_reconnect(Some(e.to_string())).await;
                            break;
                        }
                        Err(_) => {
                            tracing::warn!("ProxyPass renewal timed out after 2m");
                        }
                    }
                }
            });
        }

        // 2. Quota monitor loop (`5m` interval or earlier when >512 MiB transferred / within 5 GiB margin).
        {
            let me = Arc::clone(self);
            let c = cancel.clone();
            let acc_id = account_id.clone();
            tracker.spawn(async move {
                loop {
                    let poll_interval = {
                        let margin = me
                            .accounts
                            .list()
                            .await
                            .into_iter()
                            .find(|s| s.creds.id == acc_id)
                            .and_then(|s| s.usage)
                            .map(|u| u.remaining_bytes <= QUOTA_PROBE_MARGIN)
                            .unwrap_or(false);
                        if margin {
                            Duration::from_secs(60)
                        } else {
                            QUOTA_POLL_INTERVAL
                        }
                    };
                    tokio::select! {
                        _ = c.cancelled() => break,
                        _ = tokio::time::sleep(poll_interval) => {}
                    }
                    if me.sleeping.load(Ordering::Relaxed) {
                        continue;
                    }
                    if let Ok(rotated) = me.probe_account_quota(&acc_id).await
                        && rotated
                    {
                        tracing::info!(account = %acc_id, "quota threshold reached; rotating account");
                        let _ = me.switch_or_reconnect(None).await;
                        break;
                    }
                }
            });
        }

        // 3. Idle-sleep & status sync loop (`proxy.idle_sleep`).
        {
            let me = Arc::clone(self);
            let c = cancel.clone();
            tracker.spawn(async move {
                loop {
                    tokio::select! {
                        _ = c.cancelled() => break,
                        _ = tokio::time::sleep(IDLE_CHECK_INTERVAL) => {}
                    }
                    me.persist_status().await;

                    let sleep_after = me.config.read().await.proxy.idle_sleep.as_duration();
                    if !sleep_after.is_zero()
                        && !me.sleeping.load(Ordering::Relaxed)
                        && me.active_tunnels.load(Ordering::Relaxed) == 0
                    {
                        let idle_ms = me
                            .epoch
                            .elapsed()
                            .as_millis()
                            .saturating_sub(me.last_activity_ms.load(Ordering::Relaxed) as u128);
                        if idle_ms >= sleep_after.as_millis() {
                            tracing::info!("entering idle sleep after inactivity");
                            me.enter_sleep().await;
                            break;
                        }
                    }
                }
            });
        }

        tracker.close();
        *self.session_tasks.lock().await = tracker;
    }

    async fn stop_session_loops(&self) {
        self.session_cancel.lock().await.cancel();
        let tracker = std::mem::take(&mut *self.session_tasks.lock().await);
        tracker.close();
        tracker.wait().await;

        self.control.set_tunnel_dialer(None).await;
        if let Some(pool) = self.pool.write().await.take() {
            pool.close_all().await;
        }
        *self.active_transport.write().await = None;
    }

    async fn enter_sleep(&self) {
        self.sleeping.store(true, Ordering::Relaxed);
        self.control.set_tunnel_dialer(None).await;
        if let Some(pool) = self.pool.write().await.take() {
            pool.close_all().await;
        }
        *self.active_transport.write().await = None;
        self.emit_state(EngineState::Sleeping, None).await;
    }

    async fn renew_proxy_pass(&self, account_id: &str) -> Result<ProxyPassInfo, HeartburnError> {
        let slots = self.accounts.list().await;
        let slot = slots
            .into_iter()
            .find(|s| s.creds.id == account_id)
            .ok_or(HeartburnError::Proxy(ProxyError::NoAccounts))?;

        // Force fresh pass bypass cached value.
        let mut fresh_slot = slot;
        fresh_slot.proxy_pass = None;
        let pass = self.ensure_pass_for_account(&fresh_slot).await?;

        if let Some(ref pool) = *self.pool.read().await {
            pool.update_proxy_pass(&pass.token);
        }
        Ok(pass)
    }

    /// Probes Guardian `HEAD /api/v1/fpn/token` for `account_id`, updating usage state
    /// and returning `true` when the quota threshold requires account rotation.
    pub async fn probe_account_quota(&self, account_id: &str) -> Result<bool, HeartburnError> {
        let slots = self.accounts.list().await;
        let slot = slots
            .into_iter()
            .find(|s| s.creds.id == account_id)
            .ok_or(HeartburnError::Proxy(ProxyError::NoAccounts))?;
        let guardian = self.guardian.read().await.clone();
        let mut token = slot.creds.access_token.clone();

        let usage = match guardian.fetch_proxy_usage(&token).await {
            Ok(u) => u,
            Err(GuardianError::Unauthorized) if !slot.creds.refresh_token.is_empty() => {
                let tok = self.fxa.refresh_oauth_token(&slot.creds.refresh_token).await?;
                token = tok.access_token.clone();
                let _ = self
                    .accounts
                    .update_oauth_tokens(&slot.creds.id, tok.access_token, tok.refresh_token, tok.expires_in)
                    .await;
                guardian.fetch_proxy_usage(&token).await?
            }
            Err(e) => return Err(HeartburnError::Guardian(e)),
        };

        let _ = self.events_tx.send(EngineEvent::QuotaUpdated {
            account_id: account_id.to_owned(),
            usage: usage.clone(),
        });
        let rotate = self.accounts.update_usage(account_id, usage).await;
        Ok(rotate)
    }

    /// Rotates or reconnects seamlessly (preserving local listener socket).
    pub async fn switch_or_reconnect(
        self: &Arc<Self>,
        reason: Option<String>,
    ) -> Result<(), HeartburnError> {
        let prev = self.accounts.active_id().await;
        self.emit_state(EngineState::Reconnecting, reason).await;
        let _guard = self.connect_lock.lock().await;
        self.connect_locked(None, true).await?;
        if let Some(now_id) = self.accounts.active_id().await
            && prev.as_deref() != Some(now_id.as_str())
        {
            let _ = self.events_tx.send(EngineEvent::AccountSwitched {
                from_id: prev,
                to_id: now_id,
                reason: "failover".into(),
            });
        }
        Ok(())
    }

    /// Probes exit public IP through the live Mozilla tunnel (`https://api.ipify.org`).
    pub async fn verify_exit(self: &Arc<Self>) -> Result<String, ProxyError> {
        let pool = self.ensure_connected().await?;
        let stream = tokio::time::timeout(
            EXIT_CHECK_TIMEOUT,
            pool.open_tcp(None, "api.ipify.org", 443),
        )
        .await
        .map_err(|_| ProxyError::Transport("exit check dial timed out".into()))??;

        let tls_cfg = TlsConfig {
            server_name: "api.ipify.org".into(),
            alpn: vec![b"http/1.1".to_vec()],
            ech_config_list: None,
            tls12_only: false,
            fingerprint: TlsFingerprint::Firefox158,
        };
        let mut tls = tokio::time::timeout(EXIT_CHECK_TIMEOUT, self.tls.connect(stream, &tls_cfg))
            .await
            .map_err(|_| ProxyError::Transport("exit check TLS timed out".into()))?
            .map_err(|e| ProxyError::Transport(e.to_string()))?;

        tls.write_all(b"GET / HTTP/1.1\r\nHost: api.ipify.org\r\nConnection: close\r\n\r\n")
            .await?;
        tls.flush().await?;
        let mut raw = Vec::with_capacity(512);
        let _ = tokio::time::timeout(EXIT_CHECK_TIMEOUT, tls.read_to_end(&mut raw)).await;
        let text = String::from_utf8_lossy(&raw);
        let ip = text
            .split("\r\n\r\n")
            .nth(1)
            .map(str::trim)
            .filter(|s| s.parse::<IpAddr>().is_ok())
            .ok_or_else(|| ProxyError::Transport("exit check returned unexpected body".into()))?
            .to_owned();

        *self.exit_ip.write().await = Some(ip.clone());
        let _ = self
            .events_tx
            .send(EngineEvent::ExitVerified { exit_ip: ip.clone() });
        self.persist_status().await;
        Ok(ip)
    }

    /// Resets cached DNS/route state after OS network changes and forces reconnect.
    pub async fn on_network_changed(self: &Arc<Self>) -> Result<(), HeartburnError> {
        self.resolver.read().await.reset_cache();
        self.guardian.read().await.invalidate_route_cache().await;
        self.failover.clear();
        self.switch_or_reconnect(Some("network changed".into())).await
    }

    /// Applies updated configuration dynamically (rebuilding resolver/guardian & reconnecting if needed).
    pub async fn reload_config(self: &Arc<Self>, new_cfg: Config) -> Result<(), HeartburnError> {
        let up_socks = if !new_cfg.network.upstream_proxy_in_use().is_empty() {
            Some(UpstreamSocks5 {
                addr: new_cfg.network.upstream_proxy.clone(),
                username: new_cfg.network.upstream_proxy_username.clone(),
                password: new_cfg.network.upstream_proxy_password.clone(),
            })
        } else {
            None
        };
        let tls_dyn: Arc<dyn TlsConnector> = Arc::clone(&self.tls) as Arc<dyn TlsConnector>;
        let new_res = Arc::new(BootstrapResolver::new(
            &new_cfg.dns.servers,
            new_cfg.dns.fallback_to_system,
            self.dialer.clone(),
            tls_dyn,
            up_socks,
        )?);
        *self.resolver.write().await = new_res;
        self.control.set_network_config(new_cfg.network.clone()).await;
        *self.guardian.write().await = GuardianClient::new(
            &new_cfg.network.guardian_endpoint,
            self.control.clone(),
            new_cfg.network.clone(),
            Arc::clone(&self.storage),
        );
        self.accounts
            .reconfigure(&new_cfg.accounts.order, new_cfg.accounts.switch_threshold_percent)
            .await;
        *self.config.write().await = new_cfg;
        self.switch_or_reconnect(Some("config reloaded".into())).await
    }

    /// Cleanly tears down all upstream pools, background tasks, and status.
    pub async fn shutdown(&self) {
        self.root_cancel.cancel();
        self.stop_session_loops().await;
        self.emit_state(EngineState::Stopped, None).await;
    }

    async fn current_transport_str(&self, configured: &str) -> String {
        self.active_transport
            .read()
            .await
            .map_or_else(|| configured.to_owned(), |t| t.as_str().to_owned())
    }

    async fn emit_state(&self, state: EngineState, error: Option<String>) {
        if let Some(ref e) = error {
            *self.last_error.write().await = Some(e.clone());
        }
        let configured_transport = self.config.read().await.proxy.transport.clone();
        let transport = self.current_transport_str(&configured_transport).await;
        let server = self
            .active_server
            .read()
            .await
            .as_ref()
            .map(ProxyCandidate::addr)
            .unwrap_or_default();
        let acc = self.accounts.active_id().await;
        let _ = self.events_tx.send(EngineEvent::StateChanged {
            state,
            server,
            transport,
            account_id: acc,
            error,
        });
        self.persist_status_with_state(state).await;
    }

    async fn persist_status(&self) {
        let cur_state = self.status_tx.borrow().state;
        self.persist_status_with_state(cur_state).await;
    }

    async fn persist_status_with_state(&self, state: EngineState) {
        let cfg = self.config.read().await.clone();
        let transport = self.current_transport_str(&cfg.proxy.transport).await;
        let srv = self.active_server.read().await.clone();
        let acc_id = self.accounts.active_id().await;
        let slot = if let Some(ref id) = acc_id {
            self.accounts
                .list()
                .await
                .into_iter()
                .find(|s| s.creds.id == *id)
        } else {
            None
        };

        let snap = EngineStatus {
            state,
            listen_addr: cfg.proxy.listen,
            transport,
            server: srv.as_ref().map(ProxyCandidate::addr).unwrap_or_default(),
            country_code: srv.as_ref().map(|s| s.country_code.clone()).unwrap_or_default(),
            country_name: srv.as_ref().map(|s| s.country_name.clone()).unwrap_or_default(),
            city: srv.as_ref().map(|s| s.city.clone()).unwrap_or_default(),
            active_account_id: acc_id,
            active_account_email: slot.as_ref().map(|s| s.creds.email.clone()),
            usage: slot.and_then(|s| s.usage),
            active_tunnels: self.active_tunnels.load(Ordering::Relaxed),
            bytes_rx: self.bytes_rx.load(Ordering::Relaxed),
            bytes_tx: self.bytes_tx.load(Ordering::Relaxed),
            exit_ip: self.exit_ip.read().await.clone(),
            last_error: self.last_error.read().await.clone(),
            updated_at_unix: unix_now(),
        };

        let _ = self.status_tx.send_replace(snap.clone());
        if let Ok(json) = serde_json::to_vec_pretty(&snap) {
            let _ = self.storage.write("status.json", &json).await;
        }
    }

    fn handle_tunnel_failure(self: &Arc<Self>, err: &ProxyError, port: u16) {
        let kind = classify_upstream_error(err, port);
        let me = Arc::clone(self);
        let msg = err.to_string();

        match kind {
            FailureKind::DestinationPortRefused | FailureKind::ClientDisconnected => {}
            FailureKind::AuthExpired => {
                tokio::spawn(async move {
                    if let Some(acc_id) = me.accounts.active_id().await
                        && me.renew_proxy_pass(&acc_id).await.is_err()
                    {
                        let _ = me.switch_or_reconnect(Some(msg)).await;
                    }
                });
            }
            FailureKind::RateLimited | FailureKind::UpstreamSessionBroken => {
                tokio::spawn(async move {
                    let srv_addr = me
                        .active_server
                        .read()
                        .await
                        .as_ref()
                        .map(ProxyCandidate::addr)
                        .unwrap_or_default();
                    let avoided = !srv_addr.is_empty() && me.failover.record_failure(&srv_addr);
                    let pool_dead = me
                        .pool
                        .read()
                        .await
                        .as_ref()
                        .map(|p| p.all_closed())
                        .unwrap_or(true);
                    if avoided || pool_dead {
                        let _ = me.switch_or_reconnect(Some(msg)).await;
                    }
                });
            }
        }
    }

    #[allow(dead_code)]
    fn maybe_trigger_byte_quota_probe(self: &Arc<Self>, added: u64) {
        let total = self.bytes_rx.fetch_add(added, Ordering::Relaxed) + added;
        let last = self.last_probe_total_bytes.load(Ordering::Relaxed);
        if total.saturating_sub(last) >= USAGE_PROBE_BYTES
            && self
                .last_probe_total_bytes
                .compare_exchange(last, total, Ordering::Relaxed, Ordering::Relaxed)
                .is_ok()
        {
            let me = Arc::clone(self);
            tokio::spawn(async move {
                if let Some(acc) = me.accounts.active_id().await
                    && let Ok(true) = me.probe_account_quota(&acc).await
                {
                    let _ = me.switch_or_reconnect(None).await;
                }
            });
        }
    }
}

impl TunnelOpener for ProxyController {
    fn open_tcp<'a>(
        &'a self,
        _client_ip: IpAddr,
        _target_host: &'a str,
        _target_port: u16,
    ) -> Pin<Box<dyn Future<Output = Result<BoxStream, ProxyError>> + Send + 'a>> {
        // Guarded implementation prefers calling on Arc<ProxyController>; see `ControllerOpener`.
        Box::pin(async {
            Err(ProxyError::Transport(
                "use ControllerOpener wrapper for TunnelOpener".into(),
            ))
        })
    }

    fn open_udp<'a>(
        &'a self,
        _client_ip: IpAddr,
        _target_host: &'a str,
        _target_port: u16,
    ) -> Pin<Box<dyn Future<Output = Result<UdpTunnel, ProxyError>> + Send + 'a>> {
        Box::pin(async {
            Err(ProxyError::Transport(
                "use ControllerOpener wrapper for TunnelOpener".into(),
            ))
        })
    }
}

/// Newtype wrapper enabling `Arc<ProxyController>` to implement [`TunnelOpener`] with
/// owned `Arc` wake/reconnect ergonomics.
#[derive(Debug, Clone)]
pub struct ControllerOpener(pub Arc<ProxyController>);

impl TunnelOpener for ControllerOpener {
    fn open_tcp<'a>(
        &'a self,
        client_ip: IpAddr,
        target_host: &'a str,
        target_port: u16,
    ) -> Pin<Box<dyn Future<Output = Result<BoxStream, ProxyError>> + Send + 'a>> {
        Box::pin(async move {
            self.0.note_activity();
            let pool = self.0.ensure_connected().await?;
            match pool.open_tcp(Some(client_ip), target_host, target_port).await {
                Ok(stream) => {
                    if let Some(ref srv) = *self.0.active_server.read().await {
                        self.0.failover.record_success(&srv.addr());
                    }
                    Ok(stream)
                }
                Err(err) => {
                    self.0.handle_tunnel_failure(&err, target_port);
                    Err(err)
                }
            }
        })
    }

    fn open_udp<'a>(
        &'a self,
        client_ip: IpAddr,
        target_host: &'a str,
        target_port: u16,
    ) -> Pin<Box<dyn Future<Output = Result<UdpTunnel, ProxyError>> + Send + 'a>> {
        Box::pin(async move {
            self.0.note_activity();
            let pool = self.0.ensure_connected().await?;
            match pool.open_udp(Some(client_ip), target_host, target_port).await {
                Ok(tunnel) => {
                    if let Some(ref srv) = *self.0.active_server.read().await {
                        self.0.failover.record_success(&srv.addr());
                    }
                    Ok(tunnel)
                }
                Err(err) => {
                    self.0.handle_tunnel_failure(&err, target_port);
                    Err(err)
                }
            }
        })
    }

    fn on_tunnel_opened(&self) {
        self.0.note_activity();
    }

    fn on_tunnel_closed(&self) {
        self.0.note_activity();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dialer::UpstreamSocks5;
    use crate::storage::MemoryStorage;

    #[tokio::test]
    async fn persist_status_updates_watch_without_subscribers() {
        let storage: Arc<dyn Storage> = Arc::new(MemoryStorage::new());
        let (cfg, _) = Config::load_from(storage.as_ref()).await.unwrap();
        let dialer = ProtectedDialer::with_protector(None);
        let tls = Arc::new(AdaptiveTlsConnector::new().unwrap());
        let tls_dyn: Arc<dyn TlsConnector> = tls.clone();
        let resolver = Arc::new(
            BootstrapResolver::new(
                &cfg.dns.servers,
                cfg.dns.fallback_to_system,
                dialer.clone(),
                tls_dyn,
                None::<UpstreamSocks5>,
            )
            .unwrap(),
        );
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
            .await
            .unwrap(),
        );

        let init_status = EngineStatus {
            state: EngineState::Stopped,
            listen_addr: cfg.proxy.listen.clone(),
            transport: cfg.proxy.transport.clone(),
            updated_at_unix: unix_now(),
            ..Default::default()
        };
        let (status_tx, _) = watch::channel(init_status);
        assert_eq!(status_tx.receiver_count(), 0);
        let (events_tx, mut events_rx) = broadcast::channel(16);

        let controller = ProxyController::new(
            Arc::new(RwLock::new(cfg.clone())),
            Arc::clone(&storage),
            dialer,
            tls,
            resolver_lock,
            control,
            fxa,
            guardian,
            serverlist,
            accounts,
            status_tx.clone(),
            events_tx,
            CancellationToken::new(),
        );

        *controller.active_server.write().await = Some(ProxyCandidate {
            country_code: "NL".into(),
            country_name: "Netherlands".into(),
            city: "Amsterdam".into(),
            host: "ams-1.vpn.example".into(),
            port: 443,
            weight: 100,
        });

        controller.persist_status_with_state(EngineState::Connected).await;

        let snap = status_tx.borrow().clone();
        assert_eq!(snap.state, EngineState::Connected);
        assert_eq!(snap.server, "ams-1.vpn.example:443");
        assert_eq!(snap.country_code, "NL");
        assert_eq!(snap.listen_addr, cfg.proxy.listen);
        assert_eq!(snap.transport, cfg.proxy.transport);

        let raw = storage.read("status.json").await.unwrap().unwrap();
        let disk_snap: EngineStatus = serde_json::from_slice(&raw).unwrap();
        assert_eq!(disk_snap.server, "ams-1.vpn.example:443");
        assert_eq!(disk_snap.state, EngineState::Connected);

        // When configured transport is h3 but active fallback session uses h2, status and events
        // must report "h2" rather than the configured "h3" preference.
        let mut h3_cfg = cfg.clone();
        h3_cfg.proxy.transport = "h3".into();
        *controller.config.write().await = h3_cfg;
        *controller.active_transport.write().await = Some(TransportKind::H2);
        controller.emit_state(EngineState::Connected, None).await;

        assert_eq!(status_tx.borrow().transport, "h2");
        let ev = events_rx.recv().await.unwrap();
        assert!(matches!(
            ev,
            EngineEvent::StateChanged {
                state: EngineState::Connected,
                ref transport,
                ..
            } if transport == "h2"
        ));
        let raw_fallback = storage.read("status.json").await.unwrap().unwrap();
        let disk_fallback: EngineStatus = serde_json::from_slice(&raw_fallback).unwrap();
        assert_eq!(disk_fallback.transport, "h2");

        controller.enter_sleep().await;
        assert_eq!(status_tx.borrow().transport, "h3");
    }

    #[cfg(feature = "firefox-tls")]
    #[tokio::test]
    async fn dial_candidate_pool_h3_fallback_reports_h2_and_beats_default_timeout() {
        use std::net::SocketAddr;

        use boring2::asn1::Asn1Time;
        use boring2::bn::{BigNum, MsbOption};
        use boring2::hash::MessageDigest;
        use boring2::pkey::PKey;
        use boring2::rsa::Rsa;
        use boring2::x509::extension::{
            AuthorityKeyIdentifier, BasicConstraints, KeyUsage, SubjectAlternativeName,
            SubjectKeyIdentifier,
        };
        use boring2::x509::{X509, X509NameBuilder, X509Ref};
        use rustls::RootCertStore;
        use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
        use tokio_rustls::TlsAcceptor;

        let ca_rsa = Rsa::generate(2048).unwrap();
        let ca_key = PKey::from_rsa(ca_rsa).unwrap();
        let mut ca_name = X509NameBuilder::new().unwrap();
        ca_name.append_entry_by_text("CN", "Heartburn Ctrl Test CA").unwrap();
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
        let ca_ski = SubjectKeyIdentifier::new()
            .build(&ca_builder.x509v3_context(None, None))
            .unwrap();
        ca_builder.append_extension(ca_ski).unwrap();
        ca_builder.sign(&ca_key, MessageDigest::sha256()).unwrap();
        let ca_cert = ca_builder.build();

        let leaf_rsa = Rsa::generate(2048).unwrap();
        let leaf_key = PKey::from_rsa(leaf_rsa).unwrap();
        let mut leaf_name = X509NameBuilder::new().unwrap();
        leaf_name.append_entry_by_text("CN", "127.0.0.1").unwrap();
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
        let san = SubjectAlternativeName::new()
            .ip("127.0.0.1")
            .build(&leaf_builder.x509v3_context(ctx_ref, None))
            .unwrap();
        leaf_builder.append_extension(san).unwrap();
        leaf_builder.sign(&ca_key, MessageDigest::sha256()).unwrap();
        let leaf_cert = leaf_builder.build();

        let mut roots = RootCertStore::empty();
        let (added, _) =
            roots.add_parsable_certificates([CertificateDer::from(ca_cert.to_der().unwrap())]);
        assert_eq!(added, 1);
        let roots = Arc::new(roots);

        let mut h2_server_cfg = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![CertificateDer::from(leaf_cert.to_der().unwrap())],
            PrivateKeyDer::from(PrivatePkcs8KeyDer::from(
                leaf_key.private_key_to_der_pkcs8().unwrap(),
            )),
        )
        .unwrap();
        h2_server_cfg.alpn_protocols = vec![b"h2".to_vec()];
        let acceptor = TlsAcceptor::from(Arc::new(h2_server_cfg));

        let tcp_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = tcp_listener.local_addr().unwrap().port();
        // Hold silent UDP socket on same loopback port so QUIC stalls and falls back to H2.
        let _udp_blackhole = tokio::net::UdpSocket::bind(SocketAddr::from(([127, 0, 0, 1], port)))
            .await
            .unwrap();

        let srv_cancel = CancellationToken::new();
        let srv_cancel_clone = srv_cancel.clone();
        let srv_task = tokio::spawn(async move {
            loop {
                let (tcp, _) = tokio::select! {
                    _ = srv_cancel_clone.cancelled() => break,
                    res = tcp_listener.accept() => match res {
                        Ok(pair) => pair,
                        Err(_) => break,
                    },
                };
                let acceptor = acceptor.clone();
                let conn_cancel = srv_cancel_clone.clone();
                tokio::spawn(async move {
                    if let Ok(tls) = acceptor.accept(tcp).await
                        && let Ok(mut h2_conn) = h2::server::handshake(tls).await
                    {
                        tokio::select! {
                            _ = conn_cancel.cancelled() => {}
                            _ = h2_conn.accept() => {}
                        }
                    }
                });
            }
        });

        let storage: Arc<dyn Storage> = Arc::new(MemoryStorage::new());
        let (mut cfg, _) = Config::load_from(storage.as_ref()).await.unwrap();
        cfg.proxy.transport = "h3".into();

        let dialer = ProtectedDialer::with_protector(None);
        let tls = Arc::new(AdaptiveTlsConnector::with_roots(Arc::clone(&roots)).unwrap());
        let tls_dyn: Arc<dyn TlsConnector> = tls.clone();
        let resolver = Arc::new(
            BootstrapResolver::new(&[], false, dialer.clone(), tls_dyn, None::<UpstreamSocks5>)
                .unwrap(),
        );
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
            .await
            .unwrap(),
        );
        let init_status = EngineStatus {
            state: EngineState::Stopped,
            listen_addr: cfg.proxy.listen.clone(),
            transport: cfg.proxy.transport.clone(),
            updated_at_unix: unix_now(),
            ..Default::default()
        };
        let (status_tx, _) = watch::channel(init_status);
        let (events_tx, _) = broadcast::channel(16);

        let controller = ProxyController::new(
            Arc::new(RwLock::new(cfg)),
            Arc::clone(&storage),
            dialer,
            tls,
            resolver_lock,
            control,
            fxa,
            guardian,
            serverlist,
            accounts,
            status_tx,
            events_tx,
            CancellationToken::new(),
        );

        let cand = ProxyCandidate {
            country_code: "NL".into(),
            country_name: "Netherlands".into(),
            city: "Amsterdam".into(),
            host: "127.0.0.1".into(),
            port,
            weight: 100,
        };

        let started = tokio::time::Instant::now();
        let pool = controller
            .dial_candidate_pool(
                &cand,
                TransportKind::H3,
                1,
                "HeartburnTest/1.0",
                "test-pass",
                HelloSplitMode::Off,
                IpVersionMode::Ipv4,
                resolver,
            )
            .await
            .unwrap();
        let elapsed = started.elapsed();

        assert_eq!(pool.transport(), TransportKind::H2);
        assert!(
            elapsed < Duration::from_secs(8),
            "H3->H2 fallback should beat 20s default CONNECT_TIMEOUT; elapsed={elapsed:?}"
        );

        pool.close_all().await;
        srv_cancel.cancel();
        let _ = srv_task.await;
    }
}
