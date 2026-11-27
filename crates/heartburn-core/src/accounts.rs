//! Multi-account encrypted credential storage and quota-aware failover manager (`accounts/`).

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use base64::Engine as _;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;

use crate::config::{AccountRef, DEFAULT_SWITCH_THRESHOLD_PERCENT};
use crate::error::StorageError;
use crate::guardian::{ProxyPassInfo, ProxyUsage, unix_now};
use crate::storage::Storage;

const SECRET_KEY_FILE: &str = "secret.key";
const CREDENTIALS_FILE: &str = "credentials.json";
const ACCOUNT_META_FILE: &str = "account.json";
const STATE_FILE: &str = "state.json";
const PASSWORD_PREFIX: &str = "v1:";

/// Persisted account record stored in `credentials.json`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccountCredentials {
    pub id: String,
    pub email: String,
    #[serde(default)]
    pub encrypted_password: String,
    #[serde(default)]
    pub session_token: String,
    #[serde(default)]
    pub refresh_token: String,
    #[serde(default)]
    pub access_token: String,
    #[serde(default)]
    pub access_expires_at: u64,
    #[serde(default)]
    pub device_id: String,
}

/// Active account marker saved to `account.json`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ActiveAccountMeta {
    pub active_id: Option<String>,
    pub updated_at_unix: u64,
}

/// Per-account persisted exhaustion / check snapshot (`state.json`).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AccountPersistedState {
    pub id: String,
    pub exhausted: bool,
    pub last_usage: Option<ProxyUsage>,
    pub proxy_pass: Option<ProxyPassInfo>,
}

/// Ephemeral + persisted runtime state for a single configured account.
#[derive(Debug, Clone)]
pub struct AccountSlot {
    pub creds: AccountCredentials,
    pub enabled: bool,
    pub proxy_pass: Option<ProxyPassInfo>,
    pub usage: Option<ProxyUsage>,
    pub exhausted: bool,
    pub cooldown_until: Option<Instant>,
    pub last_error: Option<String>,
}

/// Manages `secret.key` (AES-256-GCM) and `credentials.json` via [`Storage`].
#[derive(Clone)]
pub struct AccountStore {
    storage: Arc<dyn Storage>,
}

impl std::fmt::Debug for AccountStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AccountStore").finish()
    }
}

impl AccountStore {
    pub fn new(storage: Arc<dyn Storage>) -> Self {
        Self { storage }
    }

    async fn load_or_create_key(&self) -> Result<[u8; 32], StorageError> {
        if let Some(raw) = self.storage.read(SECRET_KEY_FILE).await? {
            let trimmed = String::from_utf8_lossy(&raw).trim().to_owned();
            if raw.len() == 32 {
                let mut key = [0u8; 32];
                key.copy_from_slice(&raw);
                return Ok(key);
            }
            if let Ok(decoded) = base64::engine::general_purpose::STANDARD.decode(&trimmed)
                && decoded.len() == 32
            {
                let mut key = [0u8; 32];
                key.copy_from_slice(&decoded);
                return Ok(key);
            }
        }

        let mut key = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut key);
        let b64 = base64::engine::general_purpose::STANDARD.encode(key);
        self.storage.write(SECRET_KEY_FILE, b64.as_bytes()).await?;
        Ok(key)
    }

    /// Encrypts a plaintext account password using AES-256-GCM (`v1:` + base64).
    pub async fn encrypt_password(&self, plaintext: &str) -> Result<String, StorageError> {
        if plaintext.is_empty() {
            return Ok(String::new());
        }
        let key = self.load_or_create_key().await?;
        encrypt_password_with_key(&key, plaintext)
    }

    /// Decrypts a `"v1:..."` encrypted account password.
    pub async fn decrypt_password(&self, encoded: &str) -> Result<String, StorageError> {
        if encoded.is_empty() {
            return Ok(String::new());
        }
        let key = self.load_or_create_key().await?;
        decrypt_password_with_key(&key, encoded)
    }

    /// Loads all saved accounts from `credentials.json`.
    pub async fn load_credentials(&self) -> Result<Vec<AccountCredentials>, StorageError> {
        let Some(bytes) = self.storage.read(CREDENTIALS_FILE).await? else {
            return Ok(Vec::new());
        };
        serde_json::from_slice(&bytes).map_err(|e| StorageError::Serialization(e.to_string()))
    }

    /// Persists all accounts atomically to `credentials.json`.
    pub async fn save_credentials(&self, list: &[AccountCredentials]) -> Result<(), StorageError> {
        let mut json = serde_json::to_vec_pretty(list)
            .map_err(|e| StorageError::Serialization(e.to_string()))?;
        json.push(b'\n');
        self.storage.write(CREDENTIALS_FILE, &json).await
    }

    /// Saves active account selection metadata (`account.json`).
    pub async fn save_active_meta(&self, active_id: Option<&str>) -> Result<(), StorageError> {
        let meta = ActiveAccountMeta {
            active_id: active_id.map(ToOwned::to_owned),
            updated_at_unix: unix_now(),
        };
        let json = serde_json::to_vec_pretty(&meta)
            .map_err(|e| StorageError::Serialization(e.to_string()))?;
        self.storage.write(ACCOUNT_META_FILE, &json).await
    }

    /// Saves persisted per-account usage & ProxyPass snapshot (`state.json`).
    pub async fn save_states(&self, states: &[AccountPersistedState]) -> Result<(), StorageError> {
        let json = serde_json::to_vec_pretty(states)
            .map_err(|e| StorageError::Serialization(e.to_string()))?;
        self.storage.write(STATE_FILE, &json).await
    }

    /// Loads saved per-account state (`state.json`).
    pub async fn load_states(&self) -> Result<Vec<AccountPersistedState>, StorageError> {
        let Some(bytes) = self.storage.read(STATE_FILE).await? else {
            return Ok(Vec::new());
        };
        serde_json::from_slice(&bytes).map_err(|e| StorageError::Serialization(e.to_string()))
    }
}

/// Encrypts `plaintext` with the supplied 32-byte key -> `"v1:" + base64(nonce || ct)`.
pub fn encrypt_password_with_key(key: &[u8; 32], plaintext: &str) -> Result<String, StorageError> {
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| StorageError::Serialization(format!("AES-GCM key error: {e}")))?;
    let mut nonce_bytes = [0u8; 12];
    rand::rngs::OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(nonce, plaintext.as_bytes())
        .map_err(|e| StorageError::Serialization(format!("AES-GCM encrypt error: {e}")))?;

    let mut combined = Vec::with_capacity(12 + ciphertext.len());
    combined.extend_from_slice(&nonce_bytes);
    combined.extend_from_slice(&ciphertext);
    Ok(format!(
        "{PASSWORD_PREFIX}{}",
        base64::engine::general_purpose::STANDARD.encode(combined)
    ))
}

/// Decrypts a `"v1:..."` ciphertext with the supplied 32-byte key.
pub fn decrypt_password_with_key(key: &[u8; 32], encoded: &str) -> Result<String, StorageError> {
    let payload_b64 = encoded.strip_prefix(PASSWORD_PREFIX).ok_or_else(|| {
        StorageError::Serialization("missing v1: prefix on encrypted password".into())
    })?;
    let combined = base64::engine::general_purpose::STANDARD
        .decode(payload_b64.trim())
        .map_err(|e| StorageError::Serialization(format!("base64 decode password: {e}")))?;
    if combined.len() < 12 + 16 {
        return Err(StorageError::Serialization("encrypted password truncated".into()));
    }
    let (nonce_bytes, ct) = combined.split_at(12);
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| StorageError::Serialization(format!("AES-GCM key error: {e}")))?;
    let plain = cipher
        .decrypt(Nonce::from_slice(nonce_bytes), ct)
        .map_err(|_| StorageError::Serialization("password decryption authentication failed".into()))?;
    String::from_utf8(plain).map_err(|e| StorageError::Serialization(e.to_string()))
}

/// Thread-safe multi-account rotation & failover coordinator (`accounts/manager.go`).
#[derive(Debug)]
pub struct AccountManager {
    store: AccountStore,
    slots: RwLock<Vec<AccountSlot>>,
    active_id: RwLock<Option<String>>,
    switch_threshold_percent: RwLock<f64>,
}

impl AccountManager {
    /// Loads credentials & persisted account states from `storage`, aligned to `order`.
    pub async fn load(
        storage: Arc<dyn Storage>,
        order: &[AccountRef],
        switch_threshold_percent: f64,
    ) -> Result<Self, StorageError> {
        let store = AccountStore::new(storage);
        let creds_list = store.load_credentials().await?;
        let states = store.load_states().await.unwrap_or_default();
        let state_map: HashMap<String, AccountPersistedState> =
            states.into_iter().map(|s| (s.id.clone(), s)).collect();

        let creds_map: HashMap<String, AccountCredentials> =
            creds_list.into_iter().map(|c| (c.id.clone(), c)).collect();

        let mut ordered_slots = Vec::new();
        let mut seen = std::collections::HashSet::new();

        for r in order {
            if let Some(c) = creds_map.get(&r.id) {
                let st = state_map.get(&c.id);
                ordered_slots.push(AccountSlot {
                    creds: c.clone(),
                    enabled: r.enabled,
                    proxy_pass: st.and_then(|s| s.proxy_pass.clone()),
                    usage: st.and_then(|s| s.last_usage.clone()),
                    exhausted: st.map(|s| s.exhausted).unwrap_or(false),
                    cooldown_until: None,
                    last_error: None,
                });
                seen.insert(c.id.clone());
            }
        }

        // Append any stored credentials not explicitly listed in `order`.
        for (id, c) in creds_map {
            if !seen.contains(&id) {
                let st = state_map.get(&id);
                ordered_slots.push(AccountSlot {
                    creds: c,
                    enabled: true,
                    proxy_pass: st.and_then(|s| s.proxy_pass.clone()),
                    usage: st.and_then(|s| s.last_usage.clone()),
                    exhausted: st.map(|s| s.exhausted).unwrap_or(false),
                    cooldown_until: None,
                    last_error: None,
                });
            }
        }

        let thresh = if switch_threshold_percent > 0.0 && switch_threshold_percent <= 100.0 {
            switch_threshold_percent
        } else {
            DEFAULT_SWITCH_THRESHOLD_PERCENT
        };

        Ok(Self {
            store,
            slots: RwLock::new(ordered_slots),
            active_id: RwLock::new(None),
            switch_threshold_percent: RwLock::new(thresh),
        })
    }

    pub fn store(&self) -> &AccountStore {
        &self.store
    }

    /// Updates threshold percent and order dynamically without dropping existing tokens.
    pub async fn reconfigure(&self, order: &[AccountRef], switch_threshold_percent: f64) {
        if switch_threshold_percent > 0.0 && switch_threshold_percent <= 100.0 {
            *self.switch_threshold_percent.write().await = switch_threshold_percent;
        }
        if order.is_empty() {
            return;
        }
        let mut slots = self.slots.write().await;
        let mut by_id: HashMap<String, AccountSlot> =
            slots.drain(..).map(|s| (s.creds.id.clone(), s)).collect();
        for r in order {
            if let Some(mut s) = by_id.remove(&r.id) {
                s.enabled = r.enabled;
                slots.push(s);
            }
        }
        for (_, remaining) in by_id {
            slots.push(remaining);
        }
    }

    /// Adds or updates an account in memory and `credentials.json`.
    pub async fn upsert_account(&self, creds: AccountCredentials) -> Result<(), StorageError> {
        let mut slots = self.slots.write().await;
        if let Some(existing) = slots.iter_mut().find(|s| s.creds.id == creds.id) {
            existing.creds = creds;
            existing.cooldown_until = None;
            existing.last_error = None;
        } else {
            slots.push(AccountSlot {
                creds,
                enabled: true,
                proxy_pass: None,
                usage: None,
                exhausted: false,
                cooldown_until: None,
                last_error: None,
            });
        }
        let to_save: Vec<AccountCredentials> = slots.iter().map(|s| s.creds.clone()).collect();
        drop(slots);
        self.store.save_credentials(&to_save).await
    }

    /// Removes an account by ID and persists `credentials.json`.
    pub async fn remove_account(&self, id: &str) -> Result<bool, StorageError> {
        let mut slots = self.slots.write().await;
        let before = slots.len();
        slots.retain(|s| s.creds.id != id);
        let removed = slots.len() < before;
        let to_save: Vec<AccountCredentials> = slots.iter().map(|s| s.creds.clone()).collect();
        drop(slots);
        if removed {
            let mut active = self.active_id.write().await;
            if active.as_deref() == Some(id) {
                *active = None;
            }
            self.store.save_credentials(&to_save).await?;
        }
        Ok(removed)
    }

    /// Lists cloned snapshots of all configured accounts.
    pub async fn list(&self) -> Vec<AccountSlot> {
        self.slots.read().await.clone()
    }

    /// Returns the currently active account ID if set.
    pub async fn active_id(&self) -> Option<String> {
        self.active_id.read().await.clone()
    }

    /// Picks the highest-priority enabled, non-exhausted, non-cooled-down account.
    /// If `preferred_id` is `Some`, returns it if eligible.
    pub async fn select_candidate(&self, preferred_id: Option<&str>) -> Option<AccountSlot> {
        let slots = self.slots.read().await;
        let now = Instant::now();
        let is_eligible = |s: &AccountSlot| -> bool {
            s.enabled
                && !s.exhausted
                && s.cooldown_until.map(|until| now >= until).unwrap_or(true)
        };

        if let Some(pref) = preferred_id
            && let Some(slot) = slots.iter().find(|s| s.creds.id == pref && is_eligible(s))
        {
            return Some(slot.clone());
        }
        slots.iter().find(|s| is_eligible(s)).cloned()
    }

    /// Marks `id` as currently active and saves `account.json`.
    pub async fn set_active(&self, id: &str) {
        *self.active_id.write().await = Some(id.to_owned());
        let _ = self.store.save_active_meta(Some(id)).await;
    }

    /// Updates tokens after OAuth refresh and persists `credentials.json`.
    pub async fn update_oauth_tokens(
        &self,
        id: &str,
        access_token: String,
        refresh_token: Option<String>,
        expires_in: u64,
    ) -> Result<(), StorageError> {
        let mut slots = self.slots.write().await;
        if let Some(slot) = slots.iter_mut().find(|s| s.creds.id == id) {
            slot.creds.access_token = access_token;
            if let Some(rt) = refresh_token.filter(|s| !s.is_empty()) {
                slot.creds.refresh_token = rt;
            }
            slot.creds.access_expires_at = unix_now().saturating_add(expires_in);
        }
        let to_save: Vec<AccountCredentials> = slots.iter().map(|s| s.creds.clone()).collect();
        drop(slots);
        self.store.save_credentials(&to_save).await
    }

    /// Updates cached ProxyPass JWT for `id` and persists `state.json`.
    pub async fn update_proxy_pass(&self, id: &str, pass: ProxyPassInfo) {
        {
            let mut slots = self.slots.write().await;
            if let Some(slot) = slots.iter_mut().find(|s| s.creds.id == id) {
                slot.proxy_pass = Some(pass);
                slot.last_error = None;
            }
        }
        self.persist_states().await;
    }

    /// Records fresh quota usage for `id`. Returns `true` if the configured
    /// `switch_threshold_percent` was reached or exceeded (triggering rotation).
    pub async fn update_usage(&self, id: &str, usage: ProxyUsage) -> bool {
        let threshold = *self.switch_threshold_percent.read().await;
        let should_switch =
            usage.is_exhausted() || (usage.limit_bytes > 0 && usage.used_percent() >= threshold);
        {
            let mut slots = self.slots.write().await;
            if let Some(slot) = slots.iter_mut().find(|s| s.creds.id == id) {
                slot.usage = Some(usage);
                if should_switch {
                    slot.exhausted = true;
                }
            }
        }
        self.persist_states().await;
        should_switch
    }

    /// Clears exhausted status when a fresh quota check confirms bandwidth recovered.
    pub async fn resume_after_quota_check(&self, id: &str, usage: ProxyUsage) -> bool {
        let threshold = *self.switch_threshold_percent.read().await;
        let recovered = !usage.is_exhausted()
            && (usage.limit_bytes == 0 || usage.used_percent() < threshold);
        {
            let mut slots = self.slots.write().await;
            if let Some(slot) = slots.iter_mut().find(|s| s.creds.id == id) {
                slot.usage = Some(usage);
                if recovered {
                    slot.exhausted = false;
                    slot.cooldown_until = None;
                }
            }
        }
        self.persist_states().await;
        recovered
    }

    /// Places an account on temporary failure cooldown without removing its credentials.
    pub async fn mark_error(&self, id: &str, error: String, cooldown: Duration) {
        let mut slots = self.slots.write().await;
        if let Some(slot) = slots.iter_mut().find(|s| s.creds.id == id) {
            slot.last_error = Some(error);
            slot.cooldown_until = Some(Instant::now() + cooldown);
        }
    }

    async fn persist_states(&self) {
        let states: Vec<AccountPersistedState> = {
            let slots = self.slots.read().await;
            slots
                .iter()
                .map(|s| AccountPersistedState {
                    id: s.creds.id.clone(),
                    exhausted: s.exhausted,
                    last_usage: s.usage.clone(),
                    proxy_pass: s.proxy_pass.clone(),
                })
                .collect()
        };
        let _ = self.store.save_states(&states).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::MemoryStorage;

    #[tokio::test]
    async fn password_encryption_roundtrip_via_storage() {
        let storage = Arc::new(MemoryStorage::new());
        let store = AccountStore::new(storage.clone());

        let enc = store.encrypt_password("super-secret-pass").await.unwrap();
        assert!(enc.starts_with("v1:"));
        let dec = store.decrypt_password(&enc).await.unwrap();
        assert_eq!(dec, "super-secret-pass");
        assert!(storage.read("secret.key").await.unwrap().is_some());
    }

    #[tokio::test]
    async fn multi_account_threshold_rotation_and_recovery() {
        let storage = Arc::new(MemoryStorage::new());
        let mgr = AccountManager::load(storage.clone(), &[], 90.0).await.unwrap();

        mgr.upsert_account(AccountCredentials {
            id: "acc1".into(),
            email: "one@example.com".into(),
            encrypted_password: String::new(),
            session_token: "st1".into(),
            refresh_token: "rt1".into(),
            access_token: "at1".into(),
            access_expires_at: unix_now() + 3600,
            device_id: String::new(),
        })
        .await
        .unwrap();

        mgr.upsert_account(AccountCredentials {
            id: "acc2".into(),
            email: "two@example.com".into(),
            encrypted_password: String::new(),
            session_token: "st2".into(),
            refresh_token: "rt2".into(),
            access_token: "at2".into(),
            access_expires_at: unix_now() + 3600,
            device_id: String::new(),
        })
        .await
        .unwrap();

        let first = mgr.select_candidate(None).await.unwrap();
        assert_eq!(first.creds.id, "acc1");

        // Report 92% usage (>= 90% threshold) -> acc1 rotates out, acc2 takes over.
        let rotate = mgr
            .update_usage(
                "acc1",
                ProxyUsage {
                    limit_bytes: 100,
                    remaining_bytes: 8,
                    used_bytes: 92,
                    reset_at: None,
                    checked_at: unix_now(),
                },
            )
            .await;
        assert!(rotate);

        let next = mgr.select_candidate(Some("acc1")).await.unwrap();
        assert_eq!(next.creds.id, "acc2");

        // Fresh quota reset restores acc1.
        let recovered = mgr
            .resume_after_quota_check(
                "acc1",
                ProxyUsage {
                    limit_bytes: 100,
                    remaining_bytes: 100,
                    used_bytes: 0,
                    reset_at: None,
                    checked_at: unix_now(),
                },
            )
            .await;
        assert!(recovered);
        assert_eq!(mgr.select_candidate(None).await.unwrap().creds.id, "acc1");
    }
}
