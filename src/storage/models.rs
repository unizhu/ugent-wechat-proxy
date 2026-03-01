//! Database models for WeCom KF message storage

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// KF message stored in cache
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KfMessage {
    /// Unique database ID
    pub id: i64,
    /// KF message ID (unique from WeCom)
    pub msgid: String,
    /// Customer service account ID
    pub open_kfid: String,
    /// External user ID
    pub external_userid: String,
    /// Message type: text, image, etc.
    pub msgtype: String,
    /// Message content (JSON for complex types)
    pub content: Option<String>,
    /// Origin: 3=user, 4=agent
    pub origin: Option<i32>,
    /// Unix timestamp when message was sent
    pub send_time: i64,
    /// When this record was created
    pub created_at: DateTime<Utc>,
}

impl KfMessage {
    /// Create a new KF message for storage
    pub fn new(
        msgid: String,
        open_kfid: String,
        external_userid: String,
        msgtype: String,
        content: Option<String>,
        origin: Option<i32>,
        send_time: i64,
    ) -> Self {
        Self {
            id: 0, // Will be set by database
            msgid,
            open_kfid,
            external_userid,
            msgtype,
            content,
            origin,
            send_time,
            created_at: Utc::now(),
        }
    }
}

/// Sync state for cursor-based message recovery
#[allow(dead_code)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KfSyncState {
    /// Customer service account ID
    pub open_kfid: String,
    /// Next cursor for sync_msg API
    pub cursor: Option<String>,
    /// Last successful sync time
    pub last_sync_time: DateTime<Utc>,
    /// Total messages synced
    pub message_count: i64,
}

impl KfSyncState {
    /// Create a new sync state
    #[allow(dead_code)]
    pub fn new(open_kfid: String) -> Self {
        Self {
            open_kfid,
            cursor: None,
            last_sync_time: Utc::now(),
            message_count: 0,
        }
    }
}

/// Conversation state tracking
#[allow(dead_code)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KfConversation {
    /// Unique database ID
    pub id: i64,
    /// Customer service account ID
    pub open_kfid: String,
    /// External user ID
    pub external_userid: String,
    /// Last message ID in this conversation
    pub last_msgid: Option<String>,
    /// When the last message was received
    pub last_message_at: Option<DateTime<Utc>>,
    /// Whether waiting for LLM response
    pub pending_response: bool,
    /// When this conversation was created
    pub created_at: DateTime<Utc>,
    /// When this conversation was last updated
    pub updated_at: DateTime<Utc>,
}

impl KfConversation {
    /// Create a new conversation
    #[allow(dead_code)]
    pub fn new(open_kfid: String, external_userid: String) -> Self {
        let now = Utc::now();
        Self {
            id: 0,
            open_kfid,
            external_userid,
            last_msgid: None,
            last_message_at: None,
            pending_response: false,
            created_at: now,
            updated_at: now,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_kf_message_creation() {
        let msg = KfMessage::new(
            "msg123".to_string(),
            "wk6RwaQgAA9TgoDd65jDDalYq5FZkT6w".to_string(),
            "wm6RwaQgAA4oyMBrwj3xAn5xt1fxa6ww".to_string(),
            "text".to_string(),
            Some("Hello".to_string()),
            Some(3),
            1709251200,
        );

        assert_eq!(msg.msgid, "msg123");
        assert_eq!(msg.msgtype, "text");
        assert_eq!(msg.origin, Some(3));
    }

    #[test]
    fn test_kf_sync_state_creation() {
        let state = KfSyncState::new("wk6RwaQgAA9TgoDd65jDDalYq5FZkT6w".to_string());
        assert_eq!(state.open_kfid, "wk6RwaQgAA9TgoDd65jDDalYq5FZkT6w");
        assert_eq!(state.cursor, None);
        assert_eq!(state.message_count, 0);
    }

    #[test]
    fn test_kf_conversation_creation() {
        let conv = KfConversation::new(
            "wk6RwaQgAA9TgoDd65jDDalYq5FZkT6w".to_string(),
            "wm6RwaQgAA4oyMBrwj3xAn5xt1fxa6ww".to_string(),
        );

        assert_eq!(conv.open_kfid, "wk6RwaQgAA9TgoDd65jDDalYq5FZkT6w");
        assert!(!conv.pending_response);
    }
}
