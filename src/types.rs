//! Message types for WeChat API and proxy protocol

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

// =============================================================================
// Message Source Channel
// =============================================================================

/// Message source channel - identifies whether message is from WeChat OA or WeCom
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Channel {
    /// WeChat Official Account (公众号)
    Wechat,
    /// WeCom/企业微信 (Enterprise WeChat)
    Wecom,
}

// =============================================================================
// WeChat Message Types (from/to WeChat Official Account)
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

/// Encrypted message wrapper (WeChat OA)
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename = "xml")]
pub struct EncryptedMessage {
    #[serde(rename = "ToUserName")]
    pub to_user_name: String,
    #[serde(rename = "Encrypt")]
    pub encrypt: String,
}

/// Incoming message from WeChat Official Account
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
// WeCom Message Types (from/to WeCom/企业微信)
// =============================================================================

/// WeCom webhook verification parameters (GET request)
#[derive(Debug, Clone, Deserialize)]
pub struct WecomVerifyParams {
    pub msg_signature: String,
    pub timestamp: String,
    pub nonce: String,
    pub echostr: String,
}

/// WeCom encrypted message parameters (POST request)
#[derive(Debug, Clone, Deserialize)]
pub struct WecomEncryptedParams {
    pub msg_signature: String,
    pub timestamp: String,
    pub nonce: String,
}

/// WeCom encrypted message body
#[derive(Debug, Clone, Deserialize)]
#[serde(rename = "xml")]
pub struct WecomEncryptedBody {
    #[serde(rename = "Encrypt")]
    pub encrypt: String,
}

/// Incoming message from WeCom (Enterprise WeChat)
///
/// Key difference from WeChat OA: includes `AgentID` to identify which application
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename = "xml")]
pub struct WecomMessage {
    /// CorpID of the enterprise
    #[serde(rename = "ToUserName")]
    pub to_user_name: String,
    /// UserID of the sender (internal employee) - optional for kf_msg_or_event
    #[serde(rename = "FromUserName", default)]
    pub from_user_name: Option<String>,
    #[serde(rename = "CreateTime", default)]
    pub create_time: Option<i64>,
    #[serde(rename = "MsgType", default)]
    pub msg_type: Option<String>,
    /// Application ID - key difference from WeChat OA!
    #[serde(rename = "AgentID", default)]
    pub agent_id: Option<i64>,
    #[serde(rename = "Content", default)]
    pub content: Option<String>,
    #[serde(rename = "MsgId", default)]
    pub msg_id: Option<i64>,
    #[serde(rename = "PicUrl", default)]
    pub pic_url: Option<String>,
    #[serde(rename = "MediaId", default)]
    pub media_id: Option<String>,
    #[serde(rename = "Format", default)]
    pub format: Option<String>,
    #[serde(rename = "Recognition", default)]
    pub recognition: Option<String>,
    #[serde(rename = "ThumbMediaId", default)]
    pub thumb_media_id: Option<String>,
    #[serde(rename = "Location_X", default)]
    pub location_x: Option<f64>,
    #[serde(rename = "Location_Y", default)]
    pub location_y: Option<f64>,
    #[serde(rename = "Scale", default)]
    pub scale: Option<u32>,
    #[serde(rename = "Label", default)]
    pub label: Option<String>,
    #[serde(rename = "Title", default)]
    pub title: Option<String>,
    #[serde(rename = "Description", default)]
    pub description: Option<String>,
    #[serde(rename = "Url", default)]
    pub url: Option<String>,
    /// Event type (e.g., "kf_msg_or_event")
    #[serde(rename = "Event", default)]
    pub event: Option<String>,
    #[serde(rename = "EventKey", default)]
    pub event_key: Option<String>,
    #[serde(rename = "Ticket", default)]
    pub ticket: Option<String>,
    /// Token from kf_msg_or_event callback (use to call sync_msg API)
    #[serde(rename = "Token", default)]
    pub kf_token: Option<String>,
    /// OpenKfId from kf_msg_or_event callback
    #[serde(rename = "OpenKfId", default)]
    pub open_kfid: Option<String>,
    /// KF message ID (string format from sync_msg API)
    #[serde(rename = "KfMsgId", default)]
    pub kf_msg_id: Option<String>,
}

// =============================================================================
// Proxy Protocol Types (between proxy and UGENT)
// =============================================================================

/// Proxy message direction
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Direction {
    /// From WeChat/WeCom to UGENT
    Inbound,
    /// From UGENT to WeChat/WeCom
    Outbound,
}

/// Media content type for multimedia messages
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum MediaContent {
    /// Text message
    Text { content: String },
    /// Image message
    Image {
        /// WeCom media ID
        media_id: String,
        /// Local file path after download
        #[serde(skip_serializing_if = "Option::is_none")]
        local_path: Option<String>,
        /// Base64 encoded data
        #[serde(skip_serializing_if = "Option::is_none")]
        data: Option<String>,
    },
    /// Voice message
    Voice {
        /// WeCom media ID
        media_id: String,
        /// Local file path after download
        #[serde(skip_serializing_if = "Option::is_none")]
        local_path: Option<String>,
        /// Base64 encoded data
        #[serde(skip_serializing_if = "Option::is_none")]
        data: Option<String>,
        /// Voice format (usually "amr" for WeCom)
        #[serde(skip_serializing_if = "Option::is_none")]
        format: Option<String>,
    },
}

/// Proxy message wrapper - unified message format for both channels
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyMessage {
    /// Unique message ID
    pub id: Uuid,
    /// Message source channel (WeChat or WeCom)
    pub channel: Channel,
    /// Message timestamp
    pub timestamp: DateTime<Utc>,
    /// Direction
    pub direction: Direction,
    /// Client ID (UGENT instance identifier)
    pub client_id: String,
    /// Original WeChat message (if channel is WeChat)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub wechat_message: Option<WechatMessage>,
    /// Original WeCom message (if channel is WeCom)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub wecom_message: Option<WecomMessage>,
    /// Raw XML (for passthrough)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub raw_xml: Option<String>,
    /// Media content (image, voice, etc.)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub media_content: Option<MediaContent>,
    /// Response content (for outbound)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response: Option<String>,
    /// Error message
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl ProxyMessage {
    /// Create inbound message from WeChat Official Account
    pub fn wechat_inbound(client_id: &str, message: WechatMessage, raw_xml: String) -> Self {
        Self {
            id: Uuid::new_v4(),
            channel: Channel::Wechat,
            timestamp: Utc::now(),
            direction: Direction::Inbound,
            client_id: client_id.to_string(),
            wechat_message: Some(message),
            wecom_message: None,
            raw_xml: Some(raw_xml),
            media_content: None,
            response: None,
            error: None,
        }
    }

    /// Create inbound message from WeCom (Enterprise WeChat)
    pub fn wecom_inbound(client_id: &str, message: WecomMessage, raw_xml: String) -> Self {
        Self {
            id: Uuid::new_v4(),
            channel: Channel::Wecom,
            timestamp: Utc::now(),
            direction: Direction::Inbound,
            client_id: client_id.to_string(),
            wechat_message: None,
            wecom_message: Some(message),
            raw_xml: Some(raw_xml),
            media_content: None,
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

/// Outbound artifact kind (media type)
/// This must match ugent-plugin-api's InboundAttachmentKind
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum OutboundArtifactKind {
    /// Image file (JPG, PNG)
    Image,
    /// Audio file
    #[serde(alias = "voice")]
    Audio,
    /// Video file (MP4 format)
    Video,
    /// Document file
    Document,
    /// Other file type
    #[serde(alias = "file")]
    Other,
}

/// Outbound artifact from UGENT to send via WeCom
///
/// Supports sending media files (images, voice, video, files) through the proxy.
/// The proxy will upload the file to WeCom and send it via KF API.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutboundArtifact {
    /// Type of artifact
    pub kind: OutboundArtifactKind,
    /// File name (for display purposes)
    pub name: String,
    /// Base64 encoded data (preferred for small files)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<String>,
    /// Local file path
    #[serde(skip_serializing_if = "Option::is_none")]
    pub local_path: Option<String>,
    /// Remote URL (optional, may be used as fallback)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    /// MIME type hint
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content_type: Option<String>,
    /// Caption for the artifact
    #[serde(skip_serializing_if = "Option::is_none")]
    pub caption: Option<String>,
    /// Size in bytes
    #[serde(skip_serializing_if = "Option::is_none")]
    pub size_bytes: Option<u64>,
}

/// WebSocket message types
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum WsMessage {
    /// Authentication request
    Auth { data: ClientAuth },
    /// Authentication response
    AuthResult { success: bool, message: String },
    /// Incoming message from WeChat or WeCom
    Message { data: Box<ProxyMessage> },
    /// Response to a message (updated with artifacts support)
    Response {
        original_id: Uuid,
        content: String,
        /// Artifacts to send (images, files, etc.)
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        artifacts: Vec<OutboundArtifact>,
    },
    /// Heartbeat
    Ping,
    /// Heartbeat response
    Pong,
    /// Error
    Error { code: u32, message: String },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_channel_serialize() {
        let channel = Channel::Wechat;
        assert_eq!(serde_json::to_string(&channel).unwrap(), "\"wechat\"");

        let channel = Channel::Wecom;
        assert_eq!(serde_json::to_string(&channel).unwrap(), "\"wecom\"");
    }

    #[test]
    fn test_wecom_message_parsing() {
        let xml = r#"<xml>
            <ToUserName><![CDATA[ww1234567890abcdef]]></ToUserName>
            <FromUserName><![CDATA[zhangsan]]></FromUserName>
            <CreateTime>1234567890</CreateTime>
            <MsgType><![CDATA[text]]></MsgType>
            <Content><![CDATA[Hello]]></Content>
            <MsgId>1234567890123456</MsgId>
            <AgentID>1000002</AgentID>
        </xml>"#;

        let msg: WecomMessage = serde_xml_rs::from_str(xml).unwrap();
        assert_eq!(msg.to_user_name, "ww1234567890abcdef");
        assert_eq!(msg.from_user_name, Some("zhangsan".to_string()));
        assert_eq!(msg.msg_type, Some("text".to_string()));
        assert_eq!(msg.content, Some("Hello".to_string()));
        assert_eq!(msg.agent_id, Some(1000002));
    }

    #[test]
    fn test_proxy_message_wechat() {
        let wechat_msg = WechatMessage {
            to_user_name: "gh_abc".to_string(),
            from_user_name: "openid123".to_string(),
            create_time: 1234567890,
            msg_type: MsgType::Text,
            content: Some("Test".to_string()),
            msg_id: Some(1),
            pic_url: None,
            media_id: None,
            format: None,
            recognition: None,
            thumb_media_id: None,
            location_x: None,
            location_y: None,
            scale: None,
            label: None,
            title: None,
            description: None,
            url: None,
            event: None,
            event_key: None,
            ticket: None,
        };

        let proxy = ProxyMessage::wechat_inbound("client1", wechat_msg, "<xml/>".to_string());
        assert_eq!(proxy.channel, Channel::Wechat);
        assert!(proxy.wechat_message.is_some());
        assert!(proxy.wecom_message.is_none());
    }

    #[test]
    fn test_proxy_message_wecom() {
        let wecom_msg = WecomMessage {
            to_user_name: "ww_corp".to_string(),
            from_user_name: Some("userid123".to_string()),
            create_time: Some(1234567890),
            msg_type: Some("text".to_string()),
            agent_id: Some(1000002),
            content: Some("Test".to_string()),
            msg_id: Some(1),
            pic_url: None,
            media_id: None,
            format: None,
            recognition: None,
            thumb_media_id: None,
            location_x: None,
            location_y: None,
            scale: None,
            label: None,
            title: None,
            description: None,
            url: None,
            event: None,
            event_key: None,
            ticket: None,
            kf_token: None,
            open_kfid: None,
            kf_msg_id: None,
        };

        let proxy = ProxyMessage::wecom_inbound("client1", wecom_msg, "<xml/>".to_string());
        assert_eq!(proxy.channel, Channel::Wecom);
        assert!(proxy.wechat_message.is_none());
        assert!(proxy.wecom_message.is_some());
    }

    #[test]
    fn test_outbound_artifact_kind_serialize() {
        let kind = OutboundArtifactKind::Image;
        assert_eq!(serde_json::to_string(&kind).unwrap(), "\"image\"");

        let kind = OutboundArtifactKind::Audio;
        assert_eq!(serde_json::to_string(&kind).unwrap(), "\"audio\"");

        let kind = OutboundArtifactKind::Video;
        assert_eq!(serde_json::to_string(&kind).unwrap(), "\"video\"");

        let kind = OutboundArtifactKind::Document;
        assert_eq!(serde_json::to_string(&kind).unwrap(), "\"document\"");
    }

    #[test]
    fn test_outbound_artifact_kind_alias_deserialize() {
        // Test that "voice" deserializes to Audio
        let kind: OutboundArtifactKind = serde_json::from_str("\"voice\"").unwrap();
        assert_eq!(kind, OutboundArtifactKind::Audio);

        // Test that "file" deserializes to Other
        let kind: OutboundArtifactKind = serde_json::from_str("\"file\"").unwrap();
        assert_eq!(kind, OutboundArtifactKind::Other);

        // Test that "audio" still works
        let kind: OutboundArtifactKind = serde_json::from_str("\"audio\"").unwrap();
        assert_eq!(kind, OutboundArtifactKind::Audio);
    }

    #[test]
    fn test_outbound_artifact_serialization() {
        let artifact = OutboundArtifact {
            kind: OutboundArtifactKind::Image,
            name: "test.jpg".to_string(),
            data: Some("base64data".to_string()),
            local_path: None,
            url: None,
            content_type: Some("image/jpeg".to_string()),
            caption: Some("Test image".to_string()),
            size_bytes: None,
        };

        let json = serde_json::to_string(&artifact).unwrap();
        assert!(json.contains("\"kind\":\"image\""));
        assert!(json.contains("\"name\":\"test.jpg\""));
        assert!(json.contains("\"data\":\"base64data\""));

        // Deserialize back
        let decoded: OutboundArtifact = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.kind, OutboundArtifactKind::Image);
        assert_eq!(decoded.name, "test.jpg");
        assert_eq!(decoded.data, Some("base64data".to_string()));
    }

    #[test]
    fn test_ws_message_with_artifacts() {
        let msg = WsMessage::Response {
            original_id: Uuid::nil(),
            content: "Here is the file".to_string(),
            artifacts: vec![OutboundArtifact {
                kind: OutboundArtifactKind::Document,
                name: "document.pdf".to_string(),
                data: Some("base64pdfdata".to_string()),
                local_path: None,
                url: None,
                content_type: None,
                caption: None,
                size_bytes: None,
            }],
        };

        let json = serde_json::to_string(&msg).unwrap();
        assert!(json.contains("\"type\":\"response\""));
        assert!(json.contains("\"artifacts\""));

        // Deserialize back
        let decoded: WsMessage = serde_json::from_str(&json).unwrap();
        if let WsMessage::Response { artifacts, .. } = decoded {
            assert_eq!(artifacts.len(), 1);
            assert_eq!(artifacts[0].kind, OutboundArtifactKind::Document);
        } else {
            panic!("Expected Response variant");
        }
    }
}
