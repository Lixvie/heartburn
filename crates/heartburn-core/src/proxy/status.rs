//! Structured lifecycle status snapshots & events (`proxy/status.go`).

use serde::{Deserialize, Serialize};

use crate::guardian::ProxyUsage;

/// High-level runtime connection state of the `heartburn` engine.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EngineState {
    #[default]
    Stopped,
    Starting,
    Connecting,
    Connected,
    Sleeping,
    Reconnecting,
    Error,
}

/// Complete live telemetry snapshot written to `status.json` and broadcast to embedders.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct EngineStatus {
    pub state: EngineState,
    pub listen_addr: String,
    pub transport: String,
    pub server: String,
    pub country_code: String,
    pub country_name: String,
    pub city: String,
    pub active_account_id: Option<String>,
    pub active_account_email: Option<String>,
    pub usage: Option<ProxyUsage>,
    pub active_tunnels: usize,
    pub bytes_rx: u64,
    pub bytes_tx: u64,
    pub exit_ip: Option<String>,
    pub last_error: Option<String>,
    pub updated_at_unix: u64,
}

/// Asynchronous events streamed to desktop (Tauri) and mobile (Android Kotlin) hosts.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum EngineEvent {
    StateChanged {
        state: EngineState,
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
        usage: ProxyUsage,
    },
    ExitVerified {
        exit_ip: String,
    },
    Log {
        level: String,
        message: String,
    },
}
