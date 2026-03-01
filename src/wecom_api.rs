//! WeCom API Client for async message replies

use anyhow::{Result, anyhow};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};

const WECOM_API_BASE: &str = "https://qyapi.weixin.qq.com/cgi-bin";

/// Cached WeCom access token
#[derive(Debug, Clone)]
struct CachedToken {
    token: String,
    expires_at: Instant,
}

/// WeCom API response structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WecomApiResponse {
    /// Error code (0 means success)
    pub errcode: i64,
    /// Error message
    pub errmsg: String,
}

/// WeCom access token response
#[derive(Debug, Clone, Deserialize)]
struct WecomTokenResponse {
    errcode: i64,
    errmsg: String,
    access_token: Option<String>,
    expires_in: Option<u64>,
}

/// KF sync_msg request
#[derive(Debug, Clone, Serialize)]
struct KfSyncMsgRequest {
    /// Callback token (10 min valid)
    token: String,
    /// Customer service account ID (required!)
    open_kfid: String,
    /// Cursor for pagination (optional)
    #[serde(skip_serializing_if = "Option::is_none")]
    cursor: Option<String>,
    /// Limit (default 1000)
    #[serde(skip_serializing_if = "Option::is_none")]
    limit: Option<u32>,
}

/// KF sync_msg response
#[derive(Debug, Clone, Deserialize)]
#[allow(dead_code)]
pub struct KfSyncMsgResponse {
    pub errcode: i64,
    pub errmsg: String,
    /// Next cursor for pagination
    pub next_cursor: Option<String>,
    /// Whether there are more messages
    pub has_more: Option<u32>,
    /// Message list
    pub msg_list: Option<Vec<KfMessage>>,
}

/// KF message from sync_msg API
#[derive(Debug, Clone, Deserialize)]
#[allow(dead_code)]
pub struct KfMessage {
    /// Message ID
    pub msgid: String,
    /// Customer service account ID (OpenKfId) - not present for event type
    #[serde(default)]
    pub open_kfid: Option<String>,
    /// External user ID (customer) - not present for event type
    #[serde(default)]
    pub external_userid: Option<String>,
    /// Message send time (unix timestamp)
    pub send_time: u64,
    /// Message origin: 3=customer reply, 4=system push, 5=servicer reply
    #[serde(default)]
    pub origin: Option<u32>,
    /// Servicer userid (only when origin=5)
    #[serde(default)]
    pub servicer_userid: Option<String>,
    /// Message type (string: "text", "image", "event", etc.)
    pub msgtype: String,
    /// Text content (if msgtype == "text")
    #[serde(default)]
    pub text: Option<KfTextContent>,
    /// Image content (if msgtype == "image")
    #[serde(default)]
    pub image: Option<KfMediaContent>,
    /// Voice content (if msgtype == "voice")
    #[serde(default)]
    pub voice: Option<KfMediaContent>,
    /// Video content (if msgtype == "video")
    #[serde(default)]
    pub video: Option<KfMediaContent>,
    /// File content (if msgtype == "file")
    #[serde(default)]
    pub file: Option<KfMediaContent>,
    /// Location content (if msgtype == "location")
    #[serde(default)]
    pub location: Option<KfLocationContent>,
    /// Link content (if msgtype == "link")
    #[serde(default)]
    pub link: Option<KfLinkContent>,
    /// Event content (if msgtype == "event")
    #[serde(default)]
    pub event: Option<KfEventContent>,
}

/// Text message content
#[derive(Debug, Clone, Deserialize)]
#[allow(dead_code)]
pub struct KfTextContent {
    pub content: String,
    #[serde(default)]
    pub menu_id: Option<String>,
}

/// Media message content (image, voice, video, file)
#[derive(Debug, Clone, Deserialize)]
#[allow(dead_code)]
pub struct KfMediaContent {
    pub media_id: String,
}

/// Location message content
#[derive(Debug, Clone, Deserialize)]
#[allow(dead_code)]
pub struct KfLocationContent {
    pub latitude: f64,
    pub longitude: f64,
    pub name: String,
    pub address: String,
}

/// Link message content
#[derive(Debug, Clone, Deserialize)]
#[allow(dead_code)]
pub struct KfLinkContent {
    pub title: String,
    pub desc: String,
    pub url: String,
    #[serde(default)]
    pub pic_url: Option<String>,
}

/// Event message content
#[derive(Debug, Clone, Deserialize)]
#[allow(dead_code)]
pub struct KfEventContent {
    pub event_type: String,
    pub open_kfid: String,
    pub external_userid: String,
    #[serde(default)]
    pub scene: Option<String>,
    #[serde(default)]
    pub fail_msgid: Option<String>,
    #[serde(default)]
    pub fail_type: Option<u32>,
}

/// WeCom API client for sending async messages
pub struct WecomApiClient {
    corp_id: String,
    corp_secret: String,
    agent_id: i64,
    http: Client,
    access_token: Arc<RwLock<Option<CachedToken>>>,
}

impl WecomApiClient {
    /// Create a new WeCom API client
    pub fn new(corp_id: String, corp_secret: String, agent_id: i64) -> Self {
        Self {
            corp_id,
            corp_secret,
            agent_id,
            http: Client::new(),
            access_token: Arc::new(RwLock::new(None)),
        }
    }

    /// Get access token (with caching)
    async fn get_access_token(&self) -> Result<String> {
        // Check if we have a valid cached token
        {
            let guard = self.access_token.read().await;
            if let Some(ref cached) = *guard
                && cached.expires_at > Instant::now()
            {
                debug!("Using cached WeCom access token");
                return Ok(cached.token.clone());
            }
        }

        // Get new token
        debug!("Fetching new WeCom access token");

        let url = format!(
            "{}/gettoken?corpid={}&corpsecret={}",
            WECOM_API_BASE, self.corp_id, self.corp_secret
        );

        let response = self
            .http
            .get(&url)
            .send()
            .await?
            .json::<WecomTokenResponse>()
            .await?;

        if response.errcode != 0 {
            error!(
                "Failed to get WeCom access token: {} - {}",
                response.errcode, response.errmsg
            );
            return Err(anyhow!(
                "Failed to get WeCom access token: {} - {}",
                response.errcode,
                response.errmsg
            ));
        }

        let token = response
            .access_token
            .ok_or_else(|| anyhow!("No access token in response"))?;

        // Cache the token (subtract 60 seconds for safety margin)
        let expires_in = response.expires_in.unwrap_or(7200);
        let cached = CachedToken {
            token: token.clone(),
            expires_at: Instant::now() + Duration::from_secs(expires_in.saturating_sub(60)),
        };

        {
            let mut guard = self.access_token.write().await;
            *guard = Some(cached);
        }

        info!(
            "WeCom access token cached successfully, expires in {}s",
            expires_in
        );
        Ok(token)
    }

    /// Send text message to a WeCom user
    pub async fn send_text_message(
        &self,
        user_id: &str,
        content: &str,
    ) -> Result<WecomApiResponse> {
        let token = self.get_access_token().await?;

        let url = format!("{}/message/send?access_token={}", WECOM_API_BASE, token);

        let body = serde_json::json!({
            "touser": user_id,
            "msgtype": "text",
            "agentid": self.agent_id,
            "text": {
                "content": content
            },
            "safe": 0
        });

        debug!(
            "Sending WeCom message to user {}: {} chars",
            user_id,
            content.len()
        );

        let response = self
            .http
            .post(&url)
            .json(&body)
            .send()
            .await?
            .json::<WecomApiResponse>()
            .await?;

        match response.errcode {
            0 => {
                info!("WeCom message sent successfully to user {}", user_id);
                Ok(response)
            }
            code => {
                warn!(
                    "Failed to send WeCom message: {} - {}",
                    response.errcode, response.errmsg
                );
                Err(anyhow!("WeCom API error {}: {}", code, response.errmsg))
            }
        }
    }

    /// Sync KF (Customer Service) messages using token from kf_msg_or_event callback
    ///
    /// When WeCom sends kf_msg_or_event callback, it only contains a Token.
    /// You must call this API to fetch the actual message content and external_userid.
    /// The token is valid for 10 minutes.
    pub async fn sync_kf_messages(&self, token: &str, open_kfid: &str) -> Result<KfSyncMsgResponse> {
        let access_token = self.get_access_token().await?;

        let url = format!(
            "{}/kf/sync_msg?access_token={}",
            WECOM_API_BASE, access_token
        );

        let body = KfSyncMsgRequest {
            token: token.to_string(),
            open_kfid: open_kfid.to_string(),
            cursor: None,
            limit: Some(100),
        };

        debug!(
            "Syncing KF messages with token: {}..., open_kfid: {}",
            &token[..20.min(token.len())],
            open_kfid
        );

        let response = self
            .http
            .post(&url)
            .json(&body)
            .send()
            .await?
            .json::<KfSyncMsgResponse>()
            .await?;

        if response.errcode != 0 {
            warn!(
                "Failed to sync KF messages: {} - {}",
                response.errcode, response.errmsg
            );
            return Err(anyhow!(
                "KF sync_msg API error {}: {}",
                response.errcode,
                response.errmsg
            ));
        }

        let msg_count = response.msg_list.as_ref().map(|l| l.len()).unwrap_or(0);
        info!("Synced {} KF messages", msg_count);

        Ok(response)
    }

    /// Send KF (Customer Service) text message to a user
    ///
    /// API: POST /kf/send_msg?access_token=ACCESS_TOKEN
    /// Docs: https://developer.work.weixin.qq.com/document/path/94677
    pub async fn send_kf_text_message(
        &self,
        touser: &str,
        open_kfid: &str,
        content: &str,
    ) -> Result<WecomApiResponse> {
        let access_token = self.get_access_token().await?;

        let url = format!(
            "{}/kf/send_msg?access_token={}",
            WECOM_API_BASE, access_token
        );

        let body = serde_json::json!({
            "touser": touser,
            "open_kfid": open_kfid,
            "msgtype": "text",
            "text": {
                "content": content
            }
        });

        debug!(
            "Sending KF text message to user={}, open_kfid={}",
            touser, open_kfid
        );

        let response = self
            .http
            .post(&url)
            .json(&body)
            .send()
            .await?
            .json::<WecomApiResponse>()
            .await?;

        if response.errcode != 0 {
            warn!(
                "Failed to send KF message: {} - {}",
                response.errcode, response.errmsg
            );
            return Err(anyhow!(
                "KF send_msg API error {}: {}",
                response.errcode,
                response.errmsg
            ));
        }

        info!("Sent KF text message to {} successfully", touser);
        Ok(response)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wecom_api_response_deserialize() {
        let json = r#"{"errcode":0,"errmsg":"ok"}"#;
        let response: WecomApiResponse = serde_json::from_str(json).unwrap();
        assert_eq!(response.errcode, 0);
        assert_eq!(response.errmsg, "ok");
    }

    #[test]
    fn test_wecom_api_response_error() {
        let json = r#"{"errcode":40014,"errmsg":"invalid access_token"}"#;
        let response: WecomApiResponse = serde_json::from_str(json).unwrap();
        assert_eq!(response.errcode, 40014);
        assert_eq!(response.errmsg, "invalid access_token");
    }

    #[test]
    fn test_wecom_token_response_deserialize() {
        let json = r#"{
            "errcode": 0,
            "errmsg": "ok",
            "access_token": "abc123xyz",
            "expires_in": 7200
        }"#;
        let response: WecomTokenResponse = serde_json::from_str(json).unwrap();
        assert_eq!(response.errcode, 0);
        assert_eq!(response.access_token, Some("abc123xyz".to_string()));
        assert_eq!(response.expires_in, Some(7200));
    }

    #[test]
    fn test_wecom_client_creation() {
        let client = WecomApiClient::new("ww123456".to_string(), "secret123".to_string(), 1000002);
        assert_eq!(client.corp_id, "ww123456");
        assert_eq!(client.agent_id, 1000002);
    }
}
