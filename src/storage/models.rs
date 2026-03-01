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
}
