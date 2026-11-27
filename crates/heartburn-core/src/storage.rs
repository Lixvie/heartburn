//! Storage abstraction and filesystem-backed persistence.
//!
//! `heartburn-core` never hardcodes OS-specific data directories; callers
//! pass a [`Storage`] implementation (such as [`FsStorage`] rooted at a
//! caller-chosen `data_dir`, or an in-memory store for unit tests).

use std::collections::HashMap;
use std::future::Future;
use std::io;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::{Arc, RwLock};
use std::time::Duration;

use tokio::fs;
use tokio::io::AsyncWriteExt;

use crate::error::StorageError;

/// Boxed future helper for object-safe async [`Storage`].
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Persistent key-value byte storage interface (relative keys like `"config.json"`).
pub trait Storage: Send + Sync + std::fmt::Debug {
    /// Reads all bytes stored under `key`. Returns `Ok(None)` if absent.
    fn read(&self, key: &str) -> BoxFuture<'_, Result<Option<Vec<u8>>, StorageError>>;

    /// Atomically writes `data` under `key` with private permissions (0600 on Unix).
    fn write(&self, key: &str, data: &[u8]) -> BoxFuture<'_, Result<(), StorageError>>;

    /// Removes `key` if it exists (idempotent when missing).
    fn remove(&self, key: &str) -> BoxFuture<'_, Result<(), StorageError>>;

    /// Lists keys whose names start with `prefix`.
    fn list_prefix(&self, prefix: &str) -> BoxFuture<'_, Result<Vec<String>, StorageError>>;
}

/// Validates a storage key so paths stay safely inside the data directory.
fn validate_key(key: &str) -> Result<&str, StorageError> {
    if key.is_empty()
        || key.starts_with('/')
        || key.starts_with('\\')
        || key.contains("..")
        || key.contains(':')
        || key.contains('\0')
    {
        return Err(StorageError::InvalidKey(key.to_owned()));
    }
    Ok(key)
}

/// Filesystem implementation of [`Storage`] rooted at a caller-supplied directory.
#[derive(Debug, Clone)]
pub struct FsStorage {
    root: PathBuf,
}

impl FsStorage {
    /// Creates a new [`FsStorage`] rooted at `root`.
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    /// Returns the base directory path.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Resolves a validated relative key beneath `self.root`.
    pub fn resolve_path(&self, key: &str) -> Result<PathBuf, StorageError> {
        let valid = validate_key(key)?;
        let mut path = self.root.clone();
        for seg in valid.split(['/', '\\']) {
            if seg.is_empty() || seg == "." || seg == ".." {
                return Err(StorageError::InvalidKey(key.to_owned()));
            }
            path.push(seg);
        }
        Ok(path)
    }
}

/// Writes `data` atomically to `path` with `0o600` permissions on Unix and
/// Windows file-lock retry handling on rename (matching `securefile.go`).
pub async fn write_private_atomic(path: &Path, data: &[u8]) -> Result<(), StorageError> {
    let parent = path
        .parent()
        .ok_or_else(|| StorageError::InvalidKey(path.display().to_string()))?;

    create_private_dir_all(parent).await?;

    let tmp_name = format!(
        ".{}.tmp.{}.{}",
        path.file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("file"),
        std::process::id(),
        rand::random::<u64>()
    );
    let tmp_path = parent.join(tmp_name);

    let write_res = async {
        let mut file = open_private_temp(&tmp_path).await?;
        file.write_all(data)
            .await
            .map_err(|source| io_err(&tmp_path, source))?;
        file.sync_all()
            .await
            .map_err(|source| io_err(&tmp_path, source))?;
        Ok::<(), StorageError>(())
    }
    .await;

    if let Err(err) = write_res {
        let _ = fs::remove_file(&tmp_path).await;
        return Err(err);
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(&tmp_path, std::fs::Permissions::from_mode(0o600)).await;
    }

    if let Err(err) = rename_with_retry(&tmp_path, path).await {
        let _ = fs::remove_file(&tmp_path).await;
        return Err(err);
    }

    Ok(())
}

async fn create_private_dir_all(dir: &Path) -> Result<(), StorageError> {
    #[cfg(unix)]
    {
        use std::fs::DirBuilder;
        use std::os::unix::fs::DirBuilderExt;
        let dir_owned = dir.to_path_buf();
        tokio::task::spawn_blocking(move || {
            DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(&dir_owned)
                .map_err(|source| io_err(&dir_owned, source))
        })
        .await
        .map_err(|e| StorageError::Serialization(e.to_string()))??;
    }
    #[cfg(not(unix))]
    {
        fs::create_dir_all(dir)
            .await
            .map_err(|source| io_err(dir, source))?;
    }
    Ok(())
}

async fn open_private_temp(path: &Path) -> Result<fs::File, StorageError> {
    let mut opts = fs::OpenOptions::new();
    opts.create_new(true).write(true);
    #[cfg(unix)]
    {
        opts.mode(0o600);
    }
    opts.open(path)
        .await
        .map_err(|source| io_err(path, source))
}

async fn rename_with_retry(from: &Path, to: &Path) -> Result<(), StorageError> {
    // Windows AV indexers or concurrent readers occasionally hold a short lock.
    let mut delay = Duration::from_millis(10);
    let mut last_err: Option<io::Error> = None;

    for attempt in 0..8 {
        match fs::rename(from, to).await {
            Ok(()) => return Ok(()),
            Err(err) => {
                if cfg!(windows)
                    && matches!(
                        err.kind(),
                        io::ErrorKind::PermissionDenied | io::ErrorKind::AlreadyExists
                    )
                    && attempt < 7
                {
                    let _ = fs::remove_file(to).await;
                    last_err = Some(err);
                    tokio::time::sleep(delay).await;
                    delay = (delay * 2).min(Duration::from_millis(160));
                    continue;
                }
                return Err(io_err(to, err));
            }
        }
    }

    Err(io_err(
        to,
        last_err.unwrap_or_else(|| io::Error::other("rename failed after retries")),
    ))
}

fn io_err(path: &Path, source: io::Error) -> StorageError {
    StorageError::Io {
        path: path.display().to_string(),
        source,
    }
}

impl Storage for FsStorage {
    fn read(&self, key: &str) -> BoxFuture<'_, Result<Option<Vec<u8>>, StorageError>> {
        let key = key.to_owned();
        Box::pin(async move {
            let path = self.resolve_path(&key)?;
            match fs::read(&path).await {
                Ok(bytes) => Ok(Some(bytes)),
                Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(None),
                Err(source) => Err(io_err(&path, source)),
            }
        })
    }

    fn write(&self, key: &str, data: &[u8]) -> BoxFuture<'_, Result<(), StorageError>> {
        let key = key.to_owned();
        let data = data.to_vec();
        Box::pin(async move {
            let path = self.resolve_path(&key)?;
            write_private_atomic(&path, &data).await
        })
    }

    fn remove(&self, key: &str) -> BoxFuture<'_, Result<(), StorageError>> {
        let key = key.to_owned();
        Box::pin(async move {
            let path = self.resolve_path(&key)?;
            match fs::remove_file(&path).await {
                Ok(()) => Ok(()),
                Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(()),
                Err(source) => Err(io_err(&path, source)),
            }
        })
    }

    fn list_prefix(&self, prefix: &str) -> BoxFuture<'_, Result<Vec<String>, StorageError>> {
        let prefix = prefix.to_owned();
        Box::pin(async move {
            if prefix.contains("..") || prefix.contains('\0') {
                return Err(StorageError::InvalidKey(prefix));
            }
            let mut entries = match fs::read_dir(&self.root).await {
                Ok(e) => e,
                Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
                Err(source) => return Err(io_err(&self.root, source)),
            };
            let mut out = Vec::new();
            while let Some(entry) = entries
                .next_entry()
                .await
                .map_err(|source| io_err(&self.root, source))?
            {
                let name = entry.file_name().to_string_lossy().into_owned();
                if name.starts_with(&prefix) {
                    out.push(name);
                }
            }
            out.sort();
            Ok(out)
        })
    }
}

/// Thread-safe in-memory [`Storage`] implementation useful for embedded callers and tests.
#[derive(Debug, Clone, Default)]
pub struct MemoryStorage {
    inner: Arc<RwLock<HashMap<String, Vec<u8>>>>,
}

impl MemoryStorage {
    /// Creates an empty in-memory store.
    pub fn new() -> Self {
        Self::default()
    }
}

impl Storage for MemoryStorage {
    fn read(&self, key: &str) -> BoxFuture<'_, Result<Option<Vec<u8>>, StorageError>> {
        let key = key.to_owned();
        Box::pin(async move {
            validate_key(&key)?;
            let guard = self
                .inner
                .read()
                .map_err(|_| StorageError::Serialization("memory store lock poisoned".into()))?;
            Ok(guard.get(&key).cloned())
        })
    }

    fn write(&self, key: &str, data: &[u8]) -> BoxFuture<'_, Result<(), StorageError>> {
        let key = key.to_owned();
        let data = data.to_vec();
        Box::pin(async move {
            validate_key(&key)?;
            let mut guard = self
                .inner
                .write()
                .map_err(|_| StorageError::Serialization("memory store lock poisoned".into()))?;
            guard.insert(key, data);
            Ok(())
        })
    }

    fn remove(&self, key: &str) -> BoxFuture<'_, Result<(), StorageError>> {
        let key = key.to_owned();
        Box::pin(async move {
            validate_key(&key)?;
            let mut guard = self
                .inner
                .write()
                .map_err(|_| StorageError::Serialization("memory store lock poisoned".into()))?;
            guard.remove(&key);
            Ok(())
        })
    }

    fn list_prefix(&self, prefix: &str) -> BoxFuture<'_, Result<Vec<String>, StorageError>> {
        let prefix = prefix.to_owned();
        Box::pin(async move {
            let guard = self
                .inner
                .read()
                .map_err(|_| StorageError::Serialization("memory store lock poisoned".into()))?;
            let mut keys: Vec<String> = guard
                .keys()
                .filter(|k| k.starts_with(&prefix))
                .cloned()
                .collect();
            keys.sort();
            Ok(keys)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn memory_storage_roundtrip() {
        let store = MemoryStorage::new();
        assert_eq!(store.read("config.json").await.unwrap(), None);
        store.write("config.json", b"hello").await.unwrap();
        assert_eq!(
            store.read("config.json").await.unwrap(),
            Some(b"hello".to_vec())
        );
        assert_eq!(
            store.list_prefix("conf").await.unwrap(),
            vec!["config.json".to_string()]
        );
        store.remove("config.json").await.unwrap();
        assert_eq!(store.read("config.json").await.unwrap(), None);
    }

    #[tokio::test]
    async fn storage_rejects_traversal_keys() {
        let store = MemoryStorage::new();
        assert!(matches!(
            store.write("../escape", b"x").await,
            Err(StorageError::InvalidKey(_))
        ));
        assert!(matches!(
            store.read("/abs").await,
            Err(StorageError::InvalidKey(_))
        ));
    }

    #[tokio::test]
    async fn fs_storage_roundtrip() {
        let dir = std::env::temp_dir().join(format!("heartburn-test-{}", rand::random::<u64>()));
        let store = FsStorage::new(&dir);
        store.write("secret.key", b"keydata").await.unwrap();
        assert_eq!(
            store.read("secret.key").await.unwrap(),
            Some(b"keydata".to_vec())
        );
        store.write("secret.key", b"rotated").await.unwrap();
        assert_eq!(
            store.read("secret.key").await.unwrap(),
            Some(b"rotated".to_vec())
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
