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
