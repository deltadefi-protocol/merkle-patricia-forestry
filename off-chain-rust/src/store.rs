/// Storage layer for Merkle Patricia Forestry
/// Supports both in-memory and persistent (sled) storage

use crate::helpers::NULL_HASH;
use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, Mutex};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum StoreError {
    #[error("Key not found: {0}")]
    KeyNotFound(String),
    #[error("Sled error: {0}")]
    SledError(#[from] sled::Error),
    #[error("Serialization error: {0}")]
    SerializationError(#[from] serde_json::Error),
}

pub type Result<T> = std::result::Result<T, StoreError>;

/// Batch operation for atomic updates
#[derive(Debug, Clone)]
enum BatchOp {
    Put { key: String, value: String },
    Del { key: String },
}

/// Storage backend enum
enum Backend {
    Memory(Arc<Mutex<HashMap<String, String>>>),
    Persistent(Arc<sled::Db>),
}

impl Clone for Backend {
    fn clone(&self) -> Self {
        match self {
            Backend::Memory(map) => Backend::Memory(Arc::clone(map)),
            Backend::Persistent(db) => Backend::Persistent(Arc::clone(db)),
        }
    }
}

impl std::fmt::Debug for Backend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Backend::Memory(_) => write!(f, "Backend::Memory"),
            Backend::Persistent(_) => write!(f, "Backend::Persistent"),
        }
    }
}

/// Store for trie nodes - can be in-memory or persistent
#[derive(Clone, Debug)]
pub struct Store {
    backend: Backend,
    batch: Arc<Mutex<Option<Vec<BatchOp>>>>,
}

impl Store {
    /// Create a new in-memory store
    pub fn new() -> Self {
        Store {
            backend: Backend::Memory(Arc::new(Mutex::new(HashMap::new()))),
            batch: Arc::new(Mutex::new(None)),
        }
    }

    /// Create a new persistent store backed by sled
    pub fn new_persistent<P: AsRef<Path>>(path: P) -> Result<Self> {
        let db = sled::open(path)?;
        Ok(Store {
            backend: Backend::Persistent(Arc::new(db)),
            batch: Arc::new(Mutex::new(None)),
        })
    }

    /// Execute a function within a batch transaction
    pub async fn batch<F, T>(&self, callback: F) -> Result<T>
    where
        F: FnOnce() -> std::result::Result<T, Box<dyn std::error::Error>>,
    {
        // Start batch
        {
            let mut batch_guard = self.batch.lock().unwrap();
            assert!(batch_guard.is_none(), "batch already ongoing");
            *batch_guard = Some(Vec::new());
        }

        // Execute callback
        let result = match callback() {
            Ok(r) => r,
            Err(e) => {
                // Clear batch on error
                *self.batch.lock().unwrap() = None;
                return Err(StoreError::KeyNotFound(e.to_string()));
            }
        };

        // Commit batch
        {
            let mut batch_guard = self.batch.lock().unwrap();
            let ops = batch_guard.take().unwrap();

            match &self.backend {
                Backend::Memory(map) => {
                    let mut map = map.lock().unwrap();
                    for op in ops {
                        match op {
                            BatchOp::Put { key, value } => {
                                map.insert(key, value);
                            }
                            BatchOp::Del { key } => {
                                map.remove(&key);
                            }
                        }
                    }
                }
                Backend::Persistent(db) => {
                    let mut batch = sled::Batch::default();
                    for op in ops {
                        match op {
                            BatchOp::Put { key, value } => {
                                batch.insert(key.as_bytes(), value.as_bytes());
                            }
                            BatchOp::Del { key } => {
                                batch.remove(key.as_bytes());
                            }
                        }
                    }
                    db.apply_batch(batch)?;
                }
            }
        }

        Ok(result)
    }

    /// Get a value from the store
    pub fn get(&self, key: &[u8]) -> Result<String> {
        let key_str = if key.is_empty() || key == NULL_HASH {
            hex::encode(NULL_HASH)
        } else {
            hex::encode(key)
        };

        // Check if there's a pending batch operation for this key
        let batch_guard = self.batch.lock().unwrap();
        if let Some(ref ops) = *batch_guard {
            for op in ops.iter().rev() {
                match op {
                    BatchOp::Put { key: k, value: v } if k == &key_str => {
                        return Ok(v.clone());
                    }
                    BatchOp::Del { key: k } if k == &key_str => {
                        return Err(StoreError::KeyNotFound(key_str));
                    }
                    _ => {}
                }
            }
        }
        drop(batch_guard);

        // Get from backend
        match &self.backend {
            Backend::Memory(map) => {
                let map = map.lock().unwrap();
                map.get(&key_str)
                    .cloned()
                    .ok_or_else(|| StoreError::KeyNotFound(key_str))
            }
            Backend::Persistent(db) => {
                let value = db
                    .get(key_str.as_bytes())?
                    .ok_or_else(|| StoreError::KeyNotFound(key_str.clone()))?;
                Ok(String::from_utf8_lossy(&value).to_string())
            }
        }
    }

    /// Put a value into the store
    pub fn put(&self, key: &[u8], value: &str) {
        let key_str = if key.is_empty() || key == NULL_HASH {
            hex::encode(NULL_HASH)
        } else {
            hex::encode(key)
        };

        let mut batch_guard = self.batch.lock().unwrap();
        if let Some(ref mut ops) = *batch_guard {
            ops.push(BatchOp::Put {
                key: key_str,
                value: value.to_string(),
            });
        } else {
            drop(batch_guard);
            match &self.backend {
                Backend::Memory(map) => {
                    let mut map = map.lock().unwrap();
                    map.insert(key_str, value.to_string());
                }
                Backend::Persistent(db) => {
                    let _ = db.insert(key_str.as_bytes(), value.as_bytes());
                }
            }
        }
    }

    /// Delete a value from the store
    pub fn del(&self, key: &[u8]) {
        let key_str = if key.is_empty() || key == NULL_HASH {
            hex::encode(NULL_HASH)
        } else {
            hex::encode(key)
        };

        let mut batch_guard = self.batch.lock().unwrap();
        if let Some(ref mut ops) = *batch_guard {
            ops.push(BatchOp::Del { key: key_str });
        } else {
            drop(batch_guard);
            match &self.backend {
                Backend::Memory(map) => {
                    let mut map = map.lock().unwrap();
                    map.remove(&key_str);
                }
                Backend::Persistent(db) => {
                    let _ = db.remove(key_str.as_bytes());
                }
            }
        }
    }

    /// Get the size of the store (number of keys)
    pub fn size(&self) -> usize {
        match &self.backend {
            Backend::Memory(map) => {
                let map = map.lock().unwrap();
                map.len()
            }
            Backend::Persistent(db) => db.len(),
        }
    }
}

impl Default for Store {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_memory_store() {
        let store = Store::new();
        let key = b"test_key";
        let value = "test_value";

        store.put(key, value);
        assert_eq!(store.get(key).unwrap(), value);

        store.del(key);
        assert!(store.get(key).is_err());
    }

    #[test]
    fn test_store_size() {
        let store = Store::new();
        assert_eq!(store.size(), 0);

        store.put(b"key1", "value1");
        assert_eq!(store.size(), 1);

        store.put(b"key2", "value2");
        assert_eq!(store.size(), 2);

        store.del(b"key1");
        assert_eq!(store.size(), 1);
    }
}
