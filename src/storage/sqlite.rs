//! SQLite-based message storage implementation

use std::path::Path;

use chrono::Utc;
use parking_lot::Mutex;
use rusqlite::{Connection, params};
use tracing::{debug, error, info};

use super::models::KfMessage;

/// Message storage error type
#[derive(Debug, thiserror::Error)]
pub enum StorageError {
    #[error("Database error: {0}")]
    Database(#[from] rusqlite::Error),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

/// Result type for storage operations
pub type StorageResult<T> = Result<T, StorageError>;

/// SQLite-based message store
///
/// Provides thread-safe access to the message cache database.
/// Uses a single connection with Mutex for simplicity (SQLite handles locking internally).
pub struct MessageStore {
    /// Database connection (protected by mutex for thread safety)
    conn: Mutex<Connection>,
}

impl MessageStore {
    /// Create or open a message store at the given path
    pub fn new<P: AsRef<Path>>(path: P) -> StorageResult<Self> {
        let path = path.as_ref();

        // Ensure parent directory exists
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        info!("Opening message store at {:?}", path);

        let conn = Connection::open(path)?;

        let store = Self {
            conn: Mutex::new(conn),
        };

        store.initialize_schema()?;

        Ok(store)
    }

    /// Initialize database schema
    fn initialize_schema(&self) -> StorageResult<()> {
        let conn = self.conn.lock();

        // Enable WAL mode for better concurrency
        conn.execute_batch(
            "PRAGMA journal_mode = WAL;
             PRAGMA synchronous = NORMAL;
             PRAGMA foreign_keys = ON;",
        )?;

        // Create messages table
        conn.execute(
            "CREATE TABLE IF NOT EXISTS kf_messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                msgid TEXT UNIQUE NOT NULL,
                open_kfid TEXT NOT NULL,
                external_userid TEXT NOT NULL,
                msgtype TEXT NOT NULL,
                content TEXT,
                origin INTEGER,
                send_time INTEGER NOT NULL,
                created_at TEXT NOT NULL
            )",
            [],
        )?;

        // Create indexes
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_kf_messages_kfid_user 
             ON kf_messages(open_kfid, external_userid)",
            [],
        )?;

        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_kf_messages_time 
             ON kf_messages(send_time DESC)",
            [],
        )?;

        debug!("Message store schema initialized");
        Ok(())
    }

    /// Save a message to the cache
    ///
    /// Returns `true` if the message was inserted, `false` if it was a duplicate.
    pub fn save_message(&self, msg: &KfMessage) -> StorageResult<bool> {
        let conn = self.conn.lock();
        let created_at = Utc::now().to_rfc3339();

        let result = conn.execute(
            "INSERT OR IGNORE INTO kf_messages 
             (msgid, open_kfid, external_userid, msgtype, content, origin, send_time, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                msg.msgid,
                msg.open_kfid,
                msg.external_userid,
                msg.msgtype,
                msg.content,
                msg.origin,
                msg.send_time,
                created_at,
            ],
        );

        match result {
            Ok(rows_affected) => {
                if rows_affected > 0 {
                    debug!("Saved message {} to cache", msg.msgid);
                    Ok(true)
                } else {
                    debug!("Message {} already exists in cache (duplicate)", msg.msgid);
                    Ok(false)
                }
            }
            Err(e) => {
                error!("Failed to save message {}: {}", msg.msgid, e);
                Err(e.into())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_in_memory_store() -> MessageStore {
        let conn = Connection::open_in_memory().unwrap();
        let store = MessageStore {
            conn: Mutex::new(conn),
        };
        store.initialize_schema().unwrap();
        store
    }

    #[test]
    fn test_message_store_creation() {
        let _store = create_in_memory_store();
    }

    #[test]
    fn test_save_and_duplicate_check() {
        let store = create_in_memory_store();

        let msg = KfMessage::new(
            "msg123".to_string(),
            "wk_test".to_string(),
            "wm_test".to_string(),
            "text".to_string(),
            Some("Hello".to_string()),
            Some(3),
            1709251200,
        );

        // First save should succeed
        let inserted = store.save_message(&msg).unwrap();
        assert!(inserted);

        // Second save should be detected as duplicate
        let inserted2 = store.save_message(&msg).unwrap();
        assert!(!inserted2);
    }
}
