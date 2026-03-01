//! SQLite-based message storage implementation

use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};
use parking_lot::Mutex;
use rusqlite::{Connection, OptionalExtension, params};
use tracing::{debug, error, info};

use super::models::{KfConversation, KfMessage, KfSyncState};

/// Message storage error type
#[derive(Debug, thiserror::Error)]
pub enum StorageError {
    #[error("Database error: {0}")]
    Database(#[from] rusqlite::Error),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[allow(dead_code)]
    #[error("Invalid path: {0}")]
    InvalidPath(String),
}

/// Result type for storage operations
pub type StorageResult<T> = Result<T, StorageError>;

/// SQLite-based message store
///
/// Provides thread-safe access to the message cache database.
/// Uses a single connection with Mutex for simplicity (SQLite handles locking internally).
pub struct MessageStore {
    /// Path to the database file
    path: PathBuf,
    /// Database connection (protected by mutex for thread safety)
    conn: Mutex<Connection>,
}

impl MessageStore {
    /// Create or open a message store at the given path
    pub fn new<P: AsRef<Path>>(path: P) -> StorageResult<Self> {
        let path = path.as_ref().to_path_buf();

        // Ensure parent directory exists
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        info!("Opening message store at {:?}", path);

        let conn = Connection::open(&path)?;

        let store = Self {
            path,
            conn: Mutex::new(conn),
        };

        store.initialize_schema()?;

        Ok(store)
    }

    /// Create an in-memory store (for testing)
    #[allow(dead_code)]
    pub fn new_in_memory() -> StorageResult<Self> {
        let conn = Connection::open_in_memory()?;

        let store = Self {
            path: PathBuf::from(":memory:"),
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

        // Create sync state table
        conn.execute(
            "CREATE TABLE IF NOT EXISTS kf_sync_state (
                open_kfid TEXT PRIMARY KEY,
                cursor TEXT,
                last_sync_time TEXT NOT NULL,
                message_count INTEGER DEFAULT 0
            )",
            [],
        )?;

        // Create conversations table
        conn.execute(
            "CREATE TABLE IF NOT EXISTS kf_conversations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                open_kfid TEXT NOT NULL,
                external_userid TEXT NOT NULL,
                last_msgid TEXT,
                last_message_at TEXT,
                pending_response INTEGER DEFAULT 0,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                UNIQUE(open_kfid, external_userid)
            )",
            [],
        )?;

        debug!("Message store schema initialized");
        Ok(())
    }

    /// Save a message to the cache
    /// Returns true if the message was new (inserted), false if duplicate
    pub fn save_message(&self, msg: &KfMessage) -> StorageResult<bool> {
        let conn = self.conn.lock();

        let created_at = msg.created_at.to_rfc3339();

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

    /// Check if a message already exists (by msgid)
    #[allow(dead_code)]
    pub fn is_duplicate(&self, msgid: &str) -> StorageResult<bool> {
        let conn = self.conn.lock();

        let count: i64 = conn.query_row(
            "SELECT COUNT(*) FROM kf_messages WHERE msgid = ?1",
            params![msgid],
            |row| row.get(0),
        )?;

        Ok(count > 0)
    }

    /// Get messages for a conversation (ordered by time)
    #[allow(dead_code)]
    pub fn get_conversation_messages(
        &self,
        open_kfid: &str,
        external_userid: &str,
        limit: usize,
    ) -> StorageResult<Vec<KfMessage>> {
        let conn = self.conn.lock();

        let mut stmt = conn.prepare(
            "SELECT id, msgid, open_kfid, external_userid, msgtype, content, origin, send_time, created_at
             FROM kf_messages 
             WHERE open_kfid = ?1 AND external_userid = ?2
             ORDER BY send_time DESC
             LIMIT ?3",
        )?;

        let messages = stmt
            .query_map(params![open_kfid, external_userid, limit as i64], |row| {
                Ok(KfMessage {
                    id: row.get(0)?,
                    msgid: row.get(1)?,
                    open_kfid: row.get(2)?,
                    external_userid: row.get(3)?,
                    msgtype: row.get(4)?,
                    content: row.get(5)?,
                    origin: row.get(6)?,
                    send_time: row.get(7)?,
                    created_at: DateTime::parse_from_rfc3339(&row.get::<_, String>(8)?)
                        .map(|dt| dt.with_timezone(&Utc))
                        .unwrap_or_else(|_| Utc::now()),
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;

        Ok(messages)
    }

    // =========================================================================
    // Sync State Management
    // =========================================================================

    /// Save sync cursor for a KF account
    pub fn save_sync_cursor(
        &self,
        open_kfid: &str,
        cursor: Option<&str>,
        new_message_count: i64,
    ) -> StorageResult<()> {
        let conn = self.conn.lock();
        let now = Utc::now().to_rfc3339();

        conn.execute(
            "INSERT INTO kf_sync_state (open_kfid, cursor, last_sync_time, message_count)
             VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(open_kfid) DO UPDATE SET
                cursor = excluded.cursor,
                last_sync_time = excluded.last_sync_time,
                message_count = message_count + excluded.message_count",
            params![open_kfid, cursor, now, new_message_count],
        )?;

        debug!(
            "Saved sync cursor for {}: cursor={:?}, new_messages={}",
            open_kfid, cursor, new_message_count
        );
        Ok(())
    }

    /// Get sync cursor for a KF account
    #[allow(dead_code)]
    pub fn get_sync_cursor(&self, open_kfid: &str) -> StorageResult<Option<KfSyncState>> {
        let conn = self.conn.lock();

        let mut stmt = conn.prepare(
            "SELECT open_kfid, cursor, last_sync_time, message_count 
             FROM kf_sync_state WHERE open_kfid = ?1",
        )?;

        let result = stmt
            .query_row(params![open_kfid], |row| {
                Ok(KfSyncState {
                    open_kfid: row.get(0)?,
                    cursor: row.get(1)?,
                    last_sync_time: DateTime::parse_from_rfc3339(&row.get::<_, String>(2)?)
                        .map(|dt| dt.with_timezone(&Utc))
                        .unwrap_or_else(|_| Utc::now()),
                    message_count: row.get(3)?,
                })
            })
            .optional()?;

        Ok(result)
    }

    // =========================================================================
    // Conversation State Management
    // =========================================================================

    /// Update conversation state
    pub fn update_conversation(
        &self,
        open_kfid: &str,
        external_userid: &str,
        last_msgid: &str,
        pending_response: bool,
    ) -> StorageResult<()> {
        let conn = self.conn.lock();
        let now = Utc::now().to_rfc3339();

        conn.execute(
            "INSERT INTO kf_conversations (open_kfid, external_userid, last_msgid, last_message_at, pending_response, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?6)
             ON CONFLICT(open_kfid, external_userid) DO UPDATE SET
                last_msgid = excluded.last_msgid,
                last_message_at = excluded.last_message_at,
                pending_response = excluded.pending_response,
                updated_at = excluded.updated_at",
            params![open_kfid, external_userid, last_msgid, now, pending_response as i32, now],
        )?;

        debug!(
            "Updated conversation {}/{}: pending={}",
            open_kfid, external_userid, pending_response
        );
        Ok(())
    }

    /// Get conversation state
    #[allow(dead_code)]
    pub fn get_conversation(
        &self,
        open_kfid: &str,
        external_userid: &str,
    ) -> StorageResult<Option<KfConversation>> {
        let conn = self.conn.lock();

        let mut stmt = conn.prepare(
            "SELECT id, open_kfid, external_userid, last_msgid, last_message_at, pending_response, created_at, updated_at
             FROM kf_conversations WHERE open_kfid = ?1 AND external_userid = ?2",
        )?;

        let result = stmt
            .query_row(params![open_kfid, external_userid], |row| {
                let pending: i32 = row.get(5)?;
                Ok(KfConversation {
                    id: row.get(0)?,
                    open_kfid: row.get(1)?,
                    external_userid: row.get(2)?,
                    last_msgid: row.get(3)?,
                    last_message_at: row.get::<_, Option<String>>(4)?.and_then(|s| {
                        DateTime::parse_from_rfc3339(&s)
                            .map(|dt| dt.with_timezone(&Utc))
                            .ok()
                    }),
                    pending_response: pending != 0,
                    created_at: DateTime::parse_from_rfc3339(&row.get::<_, String>(6)?)
                        .map(|dt| dt.with_timezone(&Utc))
                        .unwrap_or_else(|_| Utc::now()),
                    updated_at: DateTime::parse_from_rfc3339(&row.get::<_, String>(7)?)
                        .map(|dt| dt.with_timezone(&Utc))
                        .unwrap_or_else(|_| Utc::now()),
                })
            })
            .optional()?;

        Ok(result)
    }

    /// Mark conversation as responded (clear pending flag)
    #[allow(dead_code)]
    pub fn mark_responded(&self, open_kfid: &str, external_userid: &str) -> StorageResult<()> {
        let conn = self.conn.lock();
        let now = Utc::now().to_rfc3339();

        conn.execute(
            "UPDATE kf_conversations 
             SET pending_response = 0, updated_at = ?3
             WHERE open_kfid = ?1 AND external_userid = ?2",
            params![open_kfid, external_userid, now],
        )?;

        Ok(())
    }

    // =========================================================================
    // Cleanup
    // =========================================================================

    /// Delete messages older than the specified number of days
    #[allow(dead_code)]
    pub fn cleanup_old_messages(&self, retention_days: i64) -> StorageResult<u64> {
        let conn = self.conn.lock();
        let cutoff = Utc::now()
            .checked_sub_days(chrono::Days::new(retention_days as u64))
            .ok_or_else(|| StorageError::InvalidPath("Invalid date calculation".to_string()))?;

        let cutoff_ts = cutoff.timestamp();

        let result = conn.execute(
            "DELETE FROM kf_messages WHERE send_time < ?1",
            params![cutoff_ts],
        )?;

        if result > 0 {
            info!(
                "Cleaned up {} old messages (older than {} days)",
                result, retention_days
            );
        }

        Ok(result as u64)
    }

    /// Get database statistics
    pub fn get_stats(&self) -> StorageResult<StorageStats> {
        let conn = self.conn.lock();

        let message_count: i64 =
            conn.query_row("SELECT COUNT(*) FROM kf_messages", [], |row| row.get(0))?;

        let conversation_count: i64 =
            conn.query_row("SELECT COUNT(*) FROM kf_conversations", [], |row| {
                row.get(0)
            })?;

        let pending_count: i64 = conn.query_row(
            "SELECT COUNT(*) FROM kf_conversations WHERE pending_response = 1",
            [],
            |row| row.get(0),
        )?;

        Ok(StorageStats {
            message_count,
            conversation_count,
            pending_count,
            db_path: self.path.clone(),
        })
    }

    /// Get the database path
    pub fn path(&self) -> &Path {
        &self.path
    }
}

/// Storage statistics
#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct StorageStats {
    pub message_count: i64,
    pub conversation_count: i64,
    pub pending_count: i64,
    pub db_path: PathBuf,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_message_store_creation() {
        let store = MessageStore::new_in_memory().unwrap();
        let stats = store.get_stats().unwrap();
        assert_eq!(stats.message_count, 0);
    }

    #[test]
    fn test_save_and_duplicate_check() {
        let store = MessageStore::new_in_memory().unwrap();

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

        // Check duplicate via is_duplicate
        assert!(store.is_duplicate("msg123").unwrap());
        assert!(!store.is_duplicate("msg456").unwrap());
    }

    #[test]
    fn test_sync_state() {
        let store = MessageStore::new_in_memory().unwrap();

        // Initially no cursor
        let state = store.get_sync_cursor("wk_test").unwrap();
        assert!(state.is_none());

        // Save cursor
        store
            .save_sync_cursor("wk_test", Some("cursor123"), 5)
            .unwrap();

        // Retrieve cursor
        let state = store.get_sync_cursor("wk_test").unwrap().unwrap();
        assert_eq!(state.cursor, Some("cursor123".to_string()));
        assert_eq!(state.message_count, 5);
    }

    #[test]
    fn test_conversation_state() {
        let store = MessageStore::new_in_memory().unwrap();

        // Update conversation with pending
        store
            .update_conversation("wk_test", "wm_test", "msg123", true)
            .unwrap();

        let conv = store
            .get_conversation("wk_test", "wm_test")
            .unwrap()
            .unwrap();
        assert!(conv.pending_response);
        assert_eq!(conv.last_msgid, Some("msg123".to_string()));

        // Mark as responded
        store.mark_responded("wk_test", "wm_test").unwrap();

        let conv = store
            .get_conversation("wk_test", "wm_test")
            .unwrap()
            .unwrap();
        assert!(!conv.pending_response);
    }

    #[test]
    fn test_cleanup_old_messages() {
        let store = MessageStore::new_in_memory().unwrap();

        // Old message (100 days ago)
        let old_time = Utc::now()
            .checked_sub_days(chrono::Days::new(100))
            .unwrap()
            .timestamp();

        let old_msg = KfMessage::new(
            "old_msg".to_string(),
            "wk_test".to_string(),
            "wm_test".to_string(),
            "text".to_string(),
            Some("Old message".to_string()),
            Some(3),
            old_time,
        );
        store.save_message(&old_msg).unwrap();

        // New message
        let new_msg = KfMessage::new(
            "new_msg".to_string(),
            "wk_test".to_string(),
            "wm_test".to_string(),
            "text".to_string(),
            Some("New message".to_string()),
            Some(3),
            Utc::now().timestamp(),
        );
        store.save_message(&new_msg).unwrap();

        // Cleanup messages older than 30 days
        let deleted = store.cleanup_old_messages(30).unwrap();
        assert_eq!(deleted, 1);

        // Old message should be gone
        assert!(!store.is_duplicate("old_msg").unwrap());

        // New message should still exist
        assert!(store.is_duplicate("new_msg").unwrap());
    }
}
