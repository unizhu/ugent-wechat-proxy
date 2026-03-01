//! Configuration management

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

/// Proxy server configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyConfig {
    // =========================================================================
    // WeChat Official Account (公众号) Configuration
    // =========================================================================
    /// WeChat token for signature verification
    pub wechat_token: String,

    /// WeChat EncodingAESKey (43 characters, optional for plain mode)
    pub wechat_encoding_aes_key: Option<String>,

    /// WeChat AppID
    pub wechat_app_id: Option<String>,

    /// WeChat AppSecret (for API calls like template messages)
    pub wechat_app_secret: Option<String>,

    /// Template ID for "Response Ready" notification
    pub template_id_response_ready: Option<String>,

    /// Webhook server bind address (receives from WeChat OA)
    #[serde(default = "default_webhook_addr")]
    pub webhook_addr: String,

    // =========================================================================
    // WeCom (企业微信) Configuration
    // =========================================================================
    /// Enable WeCom support
    #[serde(default)]
    pub wecom_enabled: bool,

    /// WeCom token for signature verification
    pub wecom_token: Option<String>,

    /// WeCom EncodingAESKey (43 characters)
    pub wecom_encoding_aes_key: Option<String>,

    /// WeCom CorpID (enterprise ID)
    pub wecom_corp_id: Option<String>,

    /// WeCom AgentID (application ID)
    pub wecom_agent_id: Option<i64>,

    /// WeCom CorpSecret (for API calls)
    pub wecom_corp_secret: Option<String>,

    /// WeCom KF Secret (for Customer Service API sync_msg)
    /// This is a separate secret from CorpSecret
    pub wecom_kf_secret: Option<String>,

    /// WeCom webhook server bind address
    #[serde(default = "default_wecom_webhook_addr")]
    pub wecom_webhook_addr: String,

    // =========================================================================
    // Common Configuration
    // =========================================================================
    /// WebSocket server bind address (UGENT connects here)
    #[serde(default = "default_websocket_addr")]
    pub websocket_addr: String,

    /// API key for authenticating UGENT clients
    pub api_key: String,

    /// Allowed client IDs (empty = allow all)
    #[serde(default)]
    pub allowed_clients: HashSet<String>,

    /// Message timeout in seconds (waiting for UGENT response)
    #[serde(default = "default_message_timeout")]
    pub message_timeout_secs: u64,

    /// Maximum connections per client
    #[serde(default = "default_max_connections")]
    pub max_connections_per_client: usize,

    /// Enable debug mode (log raw messages)
    #[serde(default)]
    pub debug_mode: bool,

    /// Rate limit: max messages per minute per client
    #[serde(default = "default_rate_limit")]
    pub rate_limit: u32,
}

fn default_webhook_addr() -> String {
    "0.0.0.0:8080".to_string()
}

fn default_wecom_webhook_addr() -> String {
    "0.0.0.0:8082".to_string()
}

fn default_websocket_addr() -> String {
    "0.0.0.0:8081".to_string()
}

fn default_message_timeout() -> u64 {
    5 // WeChat requires response within 5 seconds
}

fn default_max_connections() -> usize {
    10
}

fn default_rate_limit() -> u32 {
    100
}

impl ProxyConfig {
    /// Load configuration from environment variables
    pub fn from_env() -> Result<Self> {
        dotenvy::dotenv().ok(); // Load .env file if present

        let wechat_token = std::env::var("WECHAT_TOKEN").context("WECHAT_TOKEN is required")?;

        let api_key = std::env::var("PROXY_API_KEY").context("PROXY_API_KEY is required")?;

        Ok(Self {
            // WeChat OA config
            wechat_token,
            wechat_encoding_aes_key: std::env::var("WECHAT_ENCODING_AES_KEY").ok(),
            wechat_app_id: std::env::var("WECHAT_APP_ID").ok(),
            wechat_app_secret: std::env::var("WECHAT_APP_SECRET").ok(),
            template_id_response_ready: std::env::var("WECHAT_TEMPLATE_RESPONSE_READY").ok(),
            webhook_addr: std::env::var("WEBHOOK_ADDR").unwrap_or_else(|_| default_webhook_addr()),

            // WeCom config
            wecom_enabled: std::env::var("WECOM_ENABLED").is_ok(),
            wecom_token: std::env::var("WECOM_TOKEN").ok(),
            wecom_encoding_aes_key: std::env::var("WECOM_ENCODING_AES_KEY").ok(),
            wecom_corp_id: std::env::var("WECOM_CORP_ID").ok(),
            wecom_agent_id: std::env::var("WECOM_AGENT_ID")
                .ok()
                .and_then(|s| s.parse().ok()),
            wecom_corp_secret: std::env::var("WECOM_CORP_SECRET").ok(),
            wecom_kf_secret: std::env::var("WECOM_KF_SECRET").ok(),
            wecom_webhook_addr: std::env::var("WECOM_WEBHOOK_ADDR")
                .unwrap_or_else(|_| default_wecom_webhook_addr()),

            // Common config
            websocket_addr: std::env::var("WEBSOCKET_ADDR")
                .unwrap_or_else(|_| default_websocket_addr()),
            api_key,
            allowed_clients: std::env::var("ALLOWED_CLIENTS")
                .ok()
                .map(|s| s.split(',').map(|c| c.trim().to_string()).collect())
                .unwrap_or_default(),
            message_timeout_secs: std::env::var("MESSAGE_TIMEOUT_SECS")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(5),
            max_connections_per_client: std::env::var("MAX_CONNECTIONS_PER_CLIENT")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(10),
            debug_mode: std::env::var("DEBUG_MODE").is_ok(),
            rate_limit: std::env::var("RATE_LIMIT")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(100),
        })
    }

    /// Check if client is allowed
    pub fn is_client_allowed(&self, client_id: &str) -> bool {
        self.allowed_clients.is_empty() || self.allowed_clients.contains(client_id)
    }
}
