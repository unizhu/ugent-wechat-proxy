//! WeChat API Client for Official Account
//!
//! Handles:
//! - Access Token management (auto-refresh before expiry)
//! - Template message sending (for async notifications)
//! - Customer service message sending (within 48h window)

// These will be used in Phase 2 when integrated with broker

use anyhow::{Context, Result, anyhow};
use parking_lot::RwLock;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tracing::{debug, error, info, warn};

// =============================================================================
// API Endpoints
// =============================================================================

const TOKEN_URL: &str = "https://api.weixin.qq.com/cgi-bin/token";
const TEMPLATE_SEND_URL: &str = "https://api.weixin.qq.com/cgi-bin/message/template/send";
const CUSTOM_SEND_URL: &str = "https://api.weixin.qq.com/cgi-bin/message/custom/send";

// =============================================================================
// Access Token Management
// =============================================================================

/// Cached access token with expiry tracking
#[derive(Debug, Clone)]
struct CachedToken {
    access_token: String,
    expires_at: Instant,
}

impl CachedToken {
    fn new(access_token: String, expires_in_secs: u64) -> Self {
        // Refresh 5 minutes before expiry to be safe
        let buffer_secs = 300;
        let effective_expiry = expires_in_secs.saturating_sub(buffer_secs);
        Self {
            access_token,
            expires_at: Instant::now() + Duration::from_secs(effective_expiry),
        }
    }

    fn is_valid(&self) -> bool {
        Instant::now() < self.expires_at
    }
}

/// Token response from WeChat API
#[derive(Debug, Deserialize)]
struct TokenResponse {
    access_token: String,
    expires_in: u64,
    #[serde(default)]
    errcode: Option<i32>,
    #[serde(default)]
    errmsg: Option<String>,
}

// =============================================================================
// WeChat API Client
// =============================================================================

/// WeChat Official Account API client
#[derive(Clone)]
pub struct WechatApiClient {
    app_id: String,
    app_secret: String,
    http_client: Client,
    cached_token: Arc<RwLock<Option<CachedToken>>>,
}

impl WechatApiClient {
    /// Create a new WeChat API client
    pub fn new(app_id: String, app_secret: String) -> Self {
        Self {
            app_id,
            app_secret,
            http_client: Client::builder()
                .timeout(Duration::from_secs(10))
                .build()
                .unwrap(),
            cached_token: Arc::new(RwLock::new(None)),
        }
    }

    /// Get a valid access token (refreshes if expired)
    pub async fn get_access_token(&self) -> Result<String> {
        // Check if we have a valid cached token
        {
            let guard = self.cached_token.read();
            if let Some(ref token) = *guard
                && token.is_valid()
            {
                debug!("Using cached access token");
                return Ok(token.access_token.clone());
            }
        }

        // Need to refresh token
        self.refresh_token().await
    }

    /// Force refresh the access token
    async fn refresh_token(&self) -> Result<String> {
        debug!("Refreshing WeChat access token");

        let url = format!(
            "{}?grant_type=client_credential&appid={}&secret={}",
            TOKEN_URL, self.app_id, self.app_secret
        );

        let response = self
            .http_client
            .get(&url)
            .send()
            .await
            .context("Failed to send token request")?;

        let token_resp: TokenResponse = response
            .json()
            .await
            .context("Failed to parse token response")?;

        if let Some(errcode) = token_resp.errcode
            && errcode != 0
        {
            let errmsg = token_resp.errmsg.clone().unwrap_or_default();
            error!("WeChat token error: {} - {}", errcode, errmsg);
            return Err(anyhow!("WeChat token error: {} - {}", errcode, errmsg));
        }

        let cached = CachedToken::new(token_resp.access_token.clone(), token_resp.expires_in);

        {
            let mut guard = self.cached_token.write();
            *guard = Some(cached);
        }

        info!(
            "Successfully refreshed WeChat access token (expires in {}s)",
            token_resp.expires_in
        );
        Ok(token_resp.access_token)
    }

    /// Send a template message
    ///
    /// Used for notifications when reply is delayed beyond 48h window
    pub async fn send_template_message(
        &self,
        to_user: &str,
        template_id: &str,
        data: &TemplateMessageData,
        url: Option<&str>,
    ) -> Result<TemplateMessageResult> {
        let access_token = self.get_access_token().await?;

        let request = TemplateMessageRequest {
            touser: to_user.to_string(),
            template_id: template_id.to_string(),
            url: url.map(|s| s.to_string()),
            data: data.clone(),
        };

        let api_url = format!("{}?access_token={}", TEMPLATE_SEND_URL, access_token);

        debug!("Sending template message to user: {}", to_user);

        let response = self
            .http_client
            .post(&api_url)
            .json(&request)
            .send()
            .await
            .context("Failed to send template message request")?;

        let result: TemplateMessageResult = response
            .json()
            .await
            .context("Failed to parse template message response")?;

        if result.errcode != 0 {
            warn!(
                "Template message error: {} - {}",
                result.errcode, result.errmsg
            );
        } else {
            info!(
                "Template message sent successfully, msgid: {:?}",
                result.msgid
            );
        }

        Ok(result)
    }

    /// Send a customer service text message
    ///
    /// Can only be used within 48h of user's last message
    pub async fn send_custom_text_message(
        &self,
        to_user: &str,
        content: &str,
    ) -> Result<CustomMessageResult> {
        let access_token = self.get_access_token().await?;

        let request = CustomMessageRequest {
            touser: to_user.to_string(),
            msgtype: "text".to_string(),
            text: TextMessageContent {
                content: content.to_string(),
            },
        };

        let api_url = format!("{}?access_token={}", CUSTOM_SEND_URL, access_token);

        debug!("Sending custom text message to user: {}", to_user);

        let response = self
            .http_client
            .post(&api_url)
            .json(&request)
            .send()
            .await
            .context("Failed to send custom message request")?;

        let result: CustomMessageResult = response
            .json()
            .await
            .context("Failed to parse custom message response")?;

        if result.errcode != 0 {
            warn!(
                "Custom message error: {} - {}",
                result.errcode, result.errmsg
            );
        } else {
            info!("Custom message sent successfully to {}", to_user);
        }

        Ok(result)
    }
}

// =============================================================================
// Template Message Types
// =============================================================================

/// Template message request
#[derive(Debug, Serialize)]
struct TemplateMessageRequest {
    touser: String,
    template_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    url: Option<String>,
    data: TemplateMessageData,
}

/// Template message data (key-value pairs)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TemplateMessageData {
    #[serde(flatten)]
    pub fields: HashMap<String, TemplateField>,
}

impl TemplateMessageData {
    pub fn new() -> Self {
        Self {
            fields: HashMap::new(),
        }
    }

    pub fn add_field(mut self, key: &str, value: &str, color: Option<&str>) -> Self {
        self.fields.insert(
            key.to_string(),
            TemplateField {
                value: value.to_string(),
                color: color.map(|s| s.to_string()),
            },
        );
        self
    }
}

impl Default for TemplateMessageData {
    fn default() -> Self {
        Self::new()
    }
}

/// A single field in a template message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TemplateField {
    pub value: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub color: Option<String>,
}

/// Template message send result
#[derive(Debug, Deserialize)]
pub struct TemplateMessageResult {
    pub errcode: i32,
    pub errmsg: String,
    #[serde(default)]
    pub msgid: Option<i64>,
}

// =============================================================================
// Custom (Customer Service) Message Types
// =============================================================================

/// Custom message request
#[derive(Debug, Serialize)]
struct CustomMessageRequest {
    touser: String,
    msgtype: String,
    text: TextMessageContent,
}

/// Text message content
#[derive(Debug, Serialize)]
struct TextMessageContent {
    content: String,
}

/// Custom message send result
#[derive(Debug, Deserialize)]
pub struct CustomMessageResult {
    pub errcode: i32,
    pub errmsg: String,
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_template_message_data() {
        let data = TemplateMessageData::new()
            .add_field("first", "Hello!", Some("#173177"))
            .add_field("keyword1", "Test Value", None)
            .add_field("remark", "Click for details", None);

        let json = serde_json::to_string(&data).unwrap();
        assert!(json.contains("\"first\""));
        assert!(json.contains("Hello!"));
    }

    #[test]
    fn test_cached_token_expiry() {
        let token = CachedToken::new("test_token".to_string(), 7200);
        assert!(token.is_valid());

        // Token with short expiry but still valid (buffer won't make it negative)
        let short_token = CachedToken::new("test_token".to_string(), 400);
        // Should still be valid since 400 > 300 buffer
        assert!(short_token.is_valid());
    }
}
