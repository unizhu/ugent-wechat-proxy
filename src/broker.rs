//! Message broker - connects webhook handlers to WebSocket clients
//!
//! Handles:
//! - Forwarding messages from WeChat to UGENT via WebSocket
//! - Routing responses back to WeChat
//! - Async reply via Customer Service API when response times out

use anyhow::{Result, anyhow};
use dashmap::DashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{broadcast, oneshot};
use tracing::{debug, error, info, warn};
use uuid::Uuid;

use crate::config::ProxyConfig;
use crate::types::{ProxyMessage, WechatMessage};
use crate::wechat_api::{TemplateMessageData, WechatApiClient};

/// Pending response tracker
struct PendingResponse {
    tx: oneshot::Sender<String>,
    original_from_user: String,
    original_to_user: String,
    created_at: std::time::Instant,
}

/// Message broker state
pub struct MessageBroker {
    pub config: ProxyConfig,
    /// Pending responses: message_id -> response channel
    pending: Arc<DashMap<Uuid, PendingResponse>>,
    /// Default client ID for routing (first connected client)
    default_client: Arc<parking_lot::RwLock<Option<String>>>,
    /// Broadcast channel for sending messages to WebSocket clients
    message_tx: broadcast::Sender<ProxyMessage>,
    /// WeChat API client (for async replies via Customer Service API)
    wechat_api: Option<Arc<WechatApiClient>>,
}

impl MessageBroker {
    pub fn new(config: ProxyConfig) -> Self {
        let (message_tx, _) = broadcast::channel(256);

        // Create WeChat API client if credentials are available
        let wechat_api = config.wechat_app_id.as_ref().and_then(|app_id| {
            config
                .wechat_app_secret
                .as_ref()
                .map(|secret| Arc::new(WechatApiClient::new(app_id.clone(), secret.clone())))
        });

        Self {
            config,
            pending: Arc::new(DashMap::new()),
            default_client: Arc::new(parking_lot::RwLock::new(None)),
            message_tx,
            wechat_api,
        }
    }

    /// Subscribe to message broadcasts (for WebSocket clients)
    pub fn subscribe(&self) -> broadcast::Receiver<ProxyMessage> {
        self.message_tx.subscribe()
    }

    /// Forward message from WeChat to UGENT and wait for response
    pub async fn forward_message(&self, message: WechatMessage, raw_xml: String) -> Result<String> {
        // Get target client
        let client_id = self.get_target_client()?;

        // Create proxy message
        let proxy_msg = ProxyMessage::inbound(&client_id, message.clone(), raw_xml);

        // Create response channel
        let (tx, rx) = oneshot::channel();

        // Store user OpenID for potential async reply
        let user_openid = message.from_user_name.clone();
        let to_user = message.to_user_name.clone();

        // Register pending response with original message info for response building
        self.pending.insert(
            proxy_msg.id,
            PendingResponse {
                tx,
                original_from_user: user_openid.clone(),
                original_to_user: to_user,
                created_at: std::time::Instant::now(),
            },
        );

        // Clean up old pending responses
        self.cleanup_old_pending();

        debug!(
            "Forwarding message {} to client {}",
            proxy_msg.id, client_id
        );

        // Broadcast message to all WebSocket clients
        if let Err(e) = self.message_tx.send(proxy_msg.clone()) {
            warn!("Failed to broadcast message to WebSocket clients: {}", e);
            self.pending.remove(&proxy_msg.id);
            return Err(anyhow!("No connected WebSocket clients"));
        }

        // Wait for response with timeout
        let timeout_duration = Duration::from_secs(self.config.message_timeout_secs);
        match tokio::time::timeout(timeout_duration, rx).await {
            Ok(Ok(response)) => {
                info!("Got response for message {}", proxy_msg.id);
                Ok(response)
            }
            Ok(Err(_)) => Err(anyhow!("Response channel closed")),
            Err(_) => {
                // Remove pending response
                self.pending.remove(&proxy_msg.id);

                // Try async reply via Customer Service API
                self.try_async_reply(&user_openid).await;

                Err(anyhow!("Timeout waiting for response"))
            }
        }
    }

    /// Handle response from UGENT client
    pub async fn handle_response(
        &self,
        _client_id: &str,
        original_id: Uuid,
        content: String,
    ) -> Result<()> {
        debug!("Received response for message {} from client", original_id);

        // Find and complete pending response
        if let Some((_, pending)) = self.pending.remove(&original_id) {
            // Build proper WeChat response XML
            let response_xml = build_wechat_response(
                &pending.original_to_user,
                &pending.original_from_user,
                &content,
            );

            if pending.tx.send(response_xml).is_err() {
                warn!("Failed to send response - channel closed");
            }
        } else {
            warn!("No pending response found for message {}", original_id);
        }

        Ok(())
    }

    /// Try to send async reply via Customer Service API
    ///
    /// This is called when UGENT doesn't respond within the timeout window.
    /// Customer Service API can send messages within 48h of user's last message.
    async fn try_async_reply(&self, user_openid: &str) {
        if let Some(ref api) = self.wechat_api {
            info!(
                "Attempting async reply via Customer Service API to user {}",
                user_openid
            );

            // Send a "thinking" or "processing" message
            let message = "您的消息已收到，正在处理中，请稍候...";
            match api.send_custom_text_message(user_openid, message).await {
                Ok(result) if result.errcode == 0 => {
                    info!("Async reply sent successfully to {}", user_openid);
                }
                Ok(result) => {
                    // Error codes:
                    // 40001: Invalid access token
                    // 45015: Reply time limit exceeded (48h)
                    // 45047: Customer service message limit exceeded
                    warn!(
                        "Failed to send async reply: {} - {}",
                        result.errcode, result.errmsg
                    );

                    // If within 48h window but failed, try template message
                    if result.errcode == 45047 {
                        self.try_template_notification(user_openid).await;
                    }
                }
                Err(e) => {
                    error!("Error sending async reply: {}", e);
                }
            }
        } else {
            warn!("WeChat API client not configured, cannot send async reply");
        }
    }

    /// Try to send notification via template message
    ///
    /// Used when Customer Service API fails (e.g., rate limited)
    async fn try_template_notification(&self, user_openid: &str) {
        if let Some(ref api) = self.wechat_api {
            if let Some(ref template_id) = self.config.template_id_response_ready {
                info!("Attempting template notification to user {}", user_openid);

                let data = TemplateMessageData::new()
                    .add_field("first", "AI回复已生成", Some("#173177"))
                    .add_field("keyword1", "UGENT助手", None)
                    .add_field("keyword2", "点击查看回复", None)
                    .add_field("remark", "感谢您的耐心等待", None);

                match api
                    .send_template_message(user_openid, template_id, &data, None)
                    .await
                {
                    Ok(result) if result.errcode == 0 => {
                        info!("Template notification sent successfully to {}", user_openid);
                    }
                    Ok(result) => {
                        warn!(
                            "Failed to send template notification: {} - {}",
                            result.errcode, result.errmsg
                        );
                    }
                    Err(e) => {
                        error!("Error sending template notification: {}", e);
                    }
                }
            } else {
                warn!("Template ID not configured, cannot send template notification");
            }
        }
    }

    /// Set default client (called when first client connects)
    pub fn set_default_client(&self, client_id: String) {
        let mut guard = self.default_client.write();
        if guard.is_none() {
            *guard = Some(client_id);
        }
    }

    /// Clear default client (called when client disconnects)
    pub fn clear_default_client(&self, client_id: &str) {
        let mut guard = self.default_client.write();
        if guard.as_ref() == Some(&client_id.to_string()) {
            *guard = None;
        }
    }

    /// Get target client for routing
    fn get_target_client(&self) -> Result<String> {
        let guard = self.default_client.read();
        guard
            .clone()
            .ok_or_else(|| anyhow!("No connected clients available"))
    }

    /// Clean up old pending responses (older than 30 seconds)
    fn cleanup_old_pending(&self) {
        let now = std::time::Instant::now();
        let max_age = Duration::from_secs(30);

        self.pending
            .retain(|_, pending| now.duration_since(pending.created_at) < max_age);
    }
}

/// Build WeChat response XML
///
/// Format:
/// ```xml
/// <xml>
///   <ToUserName><![CDATA[to_user]]></ToUserName>
///   <FromUserName><![CDATA[from_user]]></FromUserName>
///   <CreateTime>timestamp</CreateTime>
///   <MsgType><![CDATA[text]]></MsgType>
///   <Content><![CDATA[content]]></Content>
/// </xml>
/// ```
fn build_wechat_response(to_user: &str, from_user: &str, content: &str) -> String {
    let timestamp = chrono::Utc::now().timestamp();
    format!(
        r#"<xml>
  <ToUserName><![CDATA[{}]]></ToUserName>
  <FromUserName><![CDATA[{}]]></FromUserName>
  <CreateTime>{}</CreateTime>
  <MsgType><![CDATA[text]]></MsgType>
  <Content><![CDATA[{}]]></Content>
</xml>"#,
        to_user, from_user, timestamp, content
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_wechat_response() {
        let response = build_wechat_response("user123", "gh_abc123", "Hello!");
        assert!(response.contains("<ToUserName><![CDATA[user123]]></ToUserName>"));
        assert!(response.contains("<FromUserName><![CDATA[gh_abc123]]></FromUserName>"));
        assert!(response.contains("<Content><![CDATA[Hello!]]></Content>"));
        assert!(response.contains("<MsgType><![CDATA[text]]></MsgType>"));
    }
}
