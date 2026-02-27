//! Message types for WeChat API and proxy protocol

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

// =============================================================================
// WeChat Message Types (from/to WeChat)
// =============================================================================

/// Message type enumeration
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum MsgType {
    Text,
    Image,
    Voice,
    Video,
    Shortvideo,
    Location,
    Link,
    Event,
}

/// WeChat webhook verification parameters (GET request)
#[derive(Debug, Clone, Deserialize)]
pub struct VerifyParams {
    pub signature: String,
    pub timestamp: String,
    pub nonce: String,
    pub echostr: String,
}

/// Encrypted message parameters (POST request)
#[derive(Debug, Clone, Deserialize)]
pub struct EncryptedParams {
    pub signature: String,
    pub timestamp: String,
    pub nonce: String,
    #[serde(default)]
    pub encrypt_type: Option<String>,
    #[serde(default)]
    pub msg_signature: Option<String>,
}

/// Encrypted message wrapper
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename = "xml")]
pub struct EncryptedMessage {
    #[serde(rename = "ToUserName")]
    pub to_user_name: String,
    #[serde(rename = "Encrypt")]
    pub encrypt: String,
}

/// Incoming message from WeChat
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename = "xml")]
pub struct WechatMessage {
    #[serde(rename = "ToUserName")]
    pub to_user_name: String,
    #[serde(rename = "FromUserName")]
    pub from_user_name: String,
    #[serde(rename = "CreateTime")]
    pub create_time: i64,
    #[serde(rename = "MsgType")]
    pub msg_type: MsgType,
    #[serde(rename = "Content")]
    pub content: Option<String>,
    #[serde(rename = "MsgId")]
    pub msg_id: Option<i64>,
    #[serde(rename = "PicUrl")]
    pub pic_url: Option<String>,
    #[serde(rename = "MediaId")]
    pub media_id: Option<String>,
    #[serde(rename = "Format")]
    pub format: Option<String>,
    #[serde(rename = "Recognition")]
    pub recognition: Option<String>,
    #[serde(rename = "ThumbMediaId")]
    pub thumb_media_id: Option<String>,
    #[serde(rename = "Location_X")]
    pub location_x: Option<f64>,
    #[serde(rename = "Location_Y")]
    pub location_y: Option<f64>,
    #[serde(rename = "Scale")]
    pub scale: Option<u32>,
    #[serde(rename = "Label")]
    pub label: Option<String>,
    #[serde(rename = "Title")]
    pub title: Option<String>,
    #[serde(rename = "Description")]
    pub description: Option<String>,
    #[serde(rename = "Url")]
    pub url: Option<String>,
    #[serde(rename = "Event")]
    pub event: Option<String>,
    #[serde(rename = "EventKey")]
    pub event_key: Option<String>,
    #[serde(rename = "Ticket")]
    pub ticket: Option<String>,
}

// =============================================================================
// Proxy Protocol Types (between proxy and UGENT)
// =============================================================================

/// Proxy message direction
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Direction {
    /// From WeChat to UGENT
    Inbound,
    /// From UGENT to WeChat
    Outbound,
}

/// Proxy message wrapper
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyMessage {
    /// Unique message ID
    pub id: Uuid,
    /// Message timestamp
    pub timestamp: DateTime<Utc>,
    /// Direction
    pub direction: Direction,
    /// Client ID (UGENT instance identifier)
    pub client_id: String,
    /// Original WeChat message
    #[serde(skip_serializing_if = "Option::is_none")]
    pub wechat_message: Option<WechatMessage>,
    /// Raw XML (for passthrough)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub raw_xml: Option<String>,
    /// Response content (for outbound)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response: Option<String>,
    /// Error message
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl ProxyMessage {
    /// Create inbound message from WeChat
    pub fn inbound(client_id: &str, message: WechatMessage, raw_xml: String) -> Self {
        Self {
            id: Uuid::new_v4(),
            timestamp: Utc::now(),
            direction: Direction::Inbound,
            client_id: client_id.to_string(),
            wechat_message: Some(message),
            raw_xml: Some(raw_xml),
            response: None,
            error: None,
        }
    }
}

/// WebSocket client authentication
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientAuth {
    pub client_id: String,
    pub api_key: String,
}

/// WebSocket message types
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum WsMessage {
    /// Authentication request
    Auth { data: ClientAuth },
    /// Authentication response
    AuthResult { success: bool, message: String },
    /// Incoming WeChat message
    Message { data: Box<ProxyMessage> },
    /// Response to a message
    Response { original_id: Uuid, content: String },
    /// Heartbeat
    Ping,
    /// Heartbeat response
    Pong,
    /// Error
    Error { code: u32, message: String },
}
