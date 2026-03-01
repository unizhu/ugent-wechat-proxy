//! Message broker - connects webhook handlers to WebSocket clients
//!
//! Handles:
//! - Forwarding messages from WeChat/WeCom to UGENT via WebSocket
//! - Routing responses back to correct channel
//! - Async reply via API when response times out

use anyhow::{Result, anyhow};
use dashmap::DashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{broadcast, oneshot};
use tracing::{debug, error, info, warn};
use uuid::Uuid;

use crate::config::ProxyConfig;
use crate::types::{Channel, ProxyMessage, WechatMessage, WecomMessage};
use crate::wechat_api::{TemplateMessageData, WechatApiClient};
use crate::wecom_api::WecomApiClient;

/// Pending response tracker
#[allow(dead_code)]
struct PendingResponse {
    /// Response channel
    tx: oneshot::Sender<String>,
    /// Original message sender (WeChat OpenID or WeCom UserID)
    original_from_user: String,
    /// Original message receiver (WeChat AppID or WeCom CorpID)
    original_to_user: String,
    /// WeCom AgentID (only for WeCom messages)
    original_agent_id: Option<i64>,
    /// Message channel (WeChat or WeCom)
    channel: Channel,
    /// When this pending response was created
    created_at: std::time::Instant,
    /// KF (Customer Service) fields - only set for KF messages
    kf_open_kfid: Option<String>,
    kf_token: Option<String>,
}

/// Message broker state
pub struct MessageBroker {
    pub config: ProxyConfig,
    /// Pending responses: message_id -> response channel
    pending: Arc<DashMap<Uuid, PendingResponse>>,
    /// Default client ID for routing (fallback)
    default_client: Arc<parking_lot::RwLock<Option<String>>>,
    /// WeChat-specific client ID (for routing WeChat messages)
    wechat_client: Arc<parking_lot::RwLock<Option<String>>>,
    /// WeCom-specific client ID (for routing WeCom messages)
    wecom_client: Arc<parking_lot::RwLock<Option<String>>>,
    /// Broadcast channel for sending messages to WebSocket clients
    message_tx: broadcast::Sender<ProxyMessage>,
    /// WeChat API client (for async replies via Customer Service API)
    wechat_api: Option<Arc<WechatApiClient>>,
    /// WeCom API client (for async replies via Application Message API)
    wecom_api: Option<Arc<WecomApiClient>>,
    /// KF (Customer Service) API client for sync_msg (uses KF secret, not corp secret)
    pub kf_api: Option<Arc<WecomApiClient>>,
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

        // Create WeCom API client if credentials are available
        let wecom_api = config
            .wecom_corp_id
            .as_ref()
            .zip(config.wecom_corp_secret.as_ref())
            .zip(config.wecom_agent_id)
            .map(|((corp_id, corp_secret), agent_id)| {
                Arc::new(WecomApiClient::new(
                    corp_id.clone(),
                    corp_secret.clone(),
                    agent_id,
                ))
            });

        // Create KF (Customer Service) API client if KF secret is available
        // KF uses a separate secret from corp secret
        let kf_api = config
            .wecom_corp_id
            .as_ref()
            .zip(config.wecom_kf_secret.as_ref())
            .map(|(corp_id, kf_secret)| {
                Arc::new(WecomApiClient::new(
                    corp_id.clone(),
                    kf_secret.clone(),
                    0, // KF doesn't use agent_id
                ))
            });

        Self {
            config,
            pending: Arc::new(DashMap::new()),
            default_client: Arc::new(parking_lot::RwLock::new(None)),
            wechat_client: Arc::new(parking_lot::RwLock::new(None)),
            wecom_client: Arc::new(parking_lot::RwLock::new(None)),
            message_tx,
            wechat_api,
            wecom_api,
            kf_api,
        }
    }

    /// Subscribe to message broadcasts (for WebSocket clients)
    pub fn subscribe(&self) -> broadcast::Receiver<ProxyMessage> {
        self.message_tx.subscribe()
    }

    /// Forward message from WeChat Official Account to UGENT
    pub async fn forward_message(&self, message: WechatMessage, raw_xml: String) -> Result<String> {
        let client_id = self.get_target_client_for_channel(Channel::Wechat)?;
        let proxy_msg = ProxyMessage::wechat_inbound(&client_id, message.clone(), raw_xml);

        let (tx, rx) = oneshot::channel();
        let user_openid = message.from_user_name.clone();
        let to_user = message.to_user_name.clone();

        self.pending.insert(
            proxy_msg.id,
            PendingResponse {
                tx,
                original_from_user: user_openid.clone(),
                original_to_user: to_user,
                original_agent_id: None,
                channel: Channel::Wechat,
                created_at: std::time::Instant::now(),
                kf_open_kfid: None,
                kf_token: None,
            },
        );

        self.cleanup_old_pending();

        debug!(
            "Forwarding WeChat message {} to client {}",
            proxy_msg.id, client_id
        );

        if let Err(e) = self.message_tx.send(proxy_msg.clone()) {
            warn!("Failed to broadcast message to WebSocket clients: {}", e);
            self.pending.remove(&proxy_msg.id);
            return Err(anyhow!("No connected WebSocket clients"));
        }

        let timeout_duration = Duration::from_secs(self.config.message_timeout_secs);
        match tokio::time::timeout(timeout_duration, rx).await {
            Ok(Ok(response)) => {
                info!("Got response for WeChat message {}", proxy_msg.id);
                Ok(response)
            }
            Ok(Err(_)) => Err(anyhow!("Response channel closed")),
            Err(_) => {
                self.pending.remove(&proxy_msg.id);
                self.try_wechat_async_reply(&user_openid).await;
                Err(anyhow!("Timeout waiting for response"))
            }
        }
    }

    /// Forward message from WeCom (Enterprise WeChat) to UGENT
    pub async fn forward_wecom_message(
        &self,
        message: WecomMessage,
        raw_xml: String,
    ) -> Result<String> {
        let client_id = self.get_target_client_for_channel(Channel::Wecom)?;
        let proxy_msg = ProxyMessage::wecom_inbound(&client_id, message.clone(), raw_xml);

        let (tx, rx) = oneshot::channel();
        // For KF messages: from_user_name = external_userid, open_kfid = customer service account
        // For regular WeCom messages: from_user_name = internal user id
        let user_id = message
            .from_user_name
            .clone()
            .unwrap_or_else(|| "unknown".to_string());
        let to_user = message.to_user_name.clone();
        let agent_id = message.agent_id;
        
        // Store KF fields for async reply
        let kf_open_kfid = message.open_kfid.clone();
        let kf_token = message.kf_token.clone();
        let is_kf_message = kf_open_kfid.is_some();

        self.pending.insert(
            proxy_msg.id,
            PendingResponse {
                tx,
                original_from_user: user_id.clone(),
                original_to_user: to_user,
                original_agent_id: agent_id,
                channel: Channel::Wecom,
                created_at: std::time::Instant::now(),
                kf_open_kfid: kf_open_kfid.clone(),
                kf_token: kf_token.clone(),
            },
        );

        self.cleanup_old_pending();
        
        debug!(
            "Forwarding WeCom message {} to client {} (KF: {}, open_kfid: {:?})",
            proxy_msg.id, client_id, is_kf_message, kf_open_kfid
        );

        if let Err(e) = self.message_tx.send(proxy_msg.clone()) {
            warn!("Failed to broadcast message to WebSocket clients: {}", e);
            self.pending.remove(&proxy_msg.id);
            return Err(anyhow!("No connected WebSocket clients"));
        }

        let timeout_duration = Duration::from_secs(self.config.message_timeout_secs);
        // For KF messages, don't wait for response - it will be sent via KF API asynchronously
        if is_kf_message {
            debug!("KF message forwarded, response will be sent via KF API");
            return Ok("success".to_string());
        }
        
        match tokio::time::timeout(timeout_duration, rx).await {
            Ok(Ok(response)) => {
                info!("Got response for WeCom message {}", proxy_msg.id);
                Ok(response)
            }
            Ok(Err(_)) => Err(anyhow!("Response channel closed")),
            Err(_) => {
                self.pending.remove(&proxy_msg.id);
                // For KF messages, use KF API for async reply
                if is_kf_message {
                    self.try_kf_async_reply(&user_id, &kf_open_kfid.unwrap()).await;
                } else {
                    self.try_wecom_async_reply(&user_id).await;
                }
                Err(anyhow!("Timeout waiting for response"))
            }
        }
    }

    /// Handle response from UGENT client (routes to correct channel)
    pub async fn handle_response(
        &self,
        _client_id: &str,
        original_id: Uuid,
        content: String,
    ) -> Result<()> {
        debug!("Received response for message {} from client", original_id);

        if let Some((_, pending)) = self.pending.remove(&original_id) {
            // Check if this is a KF (Customer Service) message
            if let (Some(kf_open_kfid), Some(kf_api)) = (&pending.kf_open_kfid, &self.kf_api) {
                // KF message - send via KF API, not XML response
                info!(
                    "Sending KF reply to user={}, open_kfid={}",
                    pending.original_from_user, kf_open_kfid
                );

                match kf_api
                    .send_kf_text_message(&pending.original_from_user, kf_open_kfid, &content)
                    .await
                {
                    Ok(resp) if resp.errcode == 0 => {
                        info!("KF reply sent successfully to {}", pending.original_from_user);
                    }
                    Ok(resp) => {
                        warn!(
                            "Failed to send KF reply: {} - {}",
                            resp.errcode, resp.errmsg
                        );
                    }
                    Err(e) => {
                        error!("Error sending KF reply: {}", e);
                    }
                }
                // For KF messages, we don't need to send via oneshot channel
                // The reply is already sent via API
                return Ok(());
            }

            // Non-KF message - build XML response
            let response_xml = match pending.channel {
                Channel::Wechat => build_wechat_response(
                    &pending.original_to_user,
                    &pending.original_from_user,
                    &content,
                ),
                Channel::Wecom => build_wecom_response(
                    &pending.original_to_user,
                    &pending.original_from_user,
                    pending.original_agent_id,
                    &content,
                ),
            };

            if pending.tx.send(response_xml).is_err() {
                warn!("Failed to send response - channel closed");
            }
        } else {
            warn!("No pending response found for message {}", original_id);
        }

        Ok(())
    }

    /// Try async reply via WeChat Customer Service API
    async fn try_wechat_async_reply(&self, user_openid: &str) {
        if let Some(ref api) = self.wechat_api {
            info!(
                "Attempting async reply via WeChat Customer Service API to user {}",
                user_openid
            );

            let message = "您的消息已收到，正在处理中，请稍候...";
            match api.send_custom_text_message(user_openid, message).await {
                Ok(result) if result.errcode == 0 => {
                    info!("WeChat async reply sent successfully to {}", user_openid);
                }
                Ok(result) => {
                    warn!(
                        "Failed to send WeChat async reply: {} - {}",
                        result.errcode, result.errmsg
                    );
                    if result.errcode == 45047 {
                        self.try_template_notification(user_openid).await;
                    }
                }
                Err(e) => {
                    error!("Error sending WeChat async reply: {}", e);
                }
            }
        }
    }

    /// Try template notification (fallback when Customer Service API fails)
    async fn try_template_notification(&self, user_openid: &str) {
        if let Some(ref api) = self.wechat_api
            && let Some(ref template_id) = self.config.template_id_response_ready
        {
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
                Ok(result) if result.errcode == 1 => {
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
        }
    }

    /// Try async reply via WeCom Application Message API
    async fn try_wecom_async_reply(&self, user_id: &str) {
        if let Some(ref api) = self.wecom_api {
            info!(
                "Attempting async reply via WeCom Application Message API to user {}",
                user_id
            );

            let message = "您的消息已收到，正在处理中，请稍候...";
            match api.send_text_message(user_id, message).await {
                Ok(result) if result.errcode == 1 => {
                    info!("WeCom async reply sent successfully to {}", user_id);
                }
                Ok(result) => {
                    warn!(
                        "Failed to send WeCom async reply: {} - {}",
                        result.errcode, result.errmsg
                    );
                }
                Err(e) => {
                    error!("Error sending WeCom async reply: {}", e);
                }
            }
        }
    }

    /// Try async reply via WeCom KF (Customer Service) API
    async fn try_kf_async_reply(&self, external_user: &str, open_kfid: &str) {
        if let Some(ref api) = self.kf_api {
            info!(
                "Attempting async reply via KF API to user={}, open_kfid={}",
                external_user, open_kfid
            );

            let message = "您的消息已收到，正在处理中，请稍候...";
            match api.send_kf_text_message(external_user, open_kfid, message).await {
                Ok(result) if result.errcode == 0 => {
                    info!("KF async reply sent successfully to {}", external_user);
                }
                Ok(result) => {
                    warn!(
                        "Failed to send KF async reply: {} - {}",
                        result.errcode, result.errmsg
                    );
                }
                Err(e) => {
                    error!("Error sending KF async reply: {}", e);
                }
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

    /// Set WeChat-specific client (called when client with "wechat" in ID connects)
    pub fn set_wechat_client(&self, client_id: String) {
        let mut guard = self.wechat_client.write();
        *guard = Some(client_id.clone());
        debug!("Set WeChat client to: {}", client_id);
    }

    /// Set WeCom-specific client (called when client with "wecom" in ID connects)
    pub fn set_wecom_client(&self, client_id: String) {
        let mut guard = self.wecom_client.write();
        *guard = Some(client_id.clone());
        debug!("Set WeCom client to: {}", client_id);
    }

    /// Clear default client (called when client disconnects)
    pub fn clear_default_client(&self, client_id: &str) {
        let mut guard = self.default_client.write();
        if guard.as_ref() == Some(&client_id.to_string()) {
            *guard = None;
        }
        // Also clear channel-specific clients
        {
            let mut wechat_guard = self.wechat_client.write();
            if wechat_guard.as_ref() == Some(&client_id.to_string()) {
                *wechat_guard = None;
            }
        }
        {
            let mut wecom_guard = self.wecom_client.write();
            if wecom_guard.as_ref() == Some(&client_id.to_string()) {
                *wecom_guard = None;
            }
        }
    }

    /// Get target client for routing (fallback to default)
    fn get_target_client(&self) -> Result<String> {
        let guard = self.default_client.read();
        guard
            .clone()
            .ok_or_else(|| anyhow!("No connected clients available"))
    }

    /// Get target client for a specific channel
    /// Routes WeChat messages to wechat_client, WeCom messages to wecom_client
    /// Falls back to default_client if channel-specific client not set
    fn get_target_client_for_channel(&self, channel: Channel) -> Result<String> {
        match channel {
            Channel::Wechat => {
                let guard = self.wechat_client.read();
                if let Some(ref client_id) = *guard {
                    return Ok(client_id.clone());
                }
            }
            Channel::Wecom => {
                let guard = self.wecom_client.read();
                if let Some(ref client_id) = *guard {
                    return Ok(client_id.clone());
                }
            }
        }
        // Fallback to default client
        self.get_target_client()
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

/// Build WeCom response XML
///
/// Note: WeCom requires AgentID in the response
fn build_wecom_response(
    to_user: &str,
    from_user: &str,
    agent_id: Option<i64>,
    content: &str,
) -> String {
    let timestamp = chrono::Utc::now().timestamp();
    let agent_xml = agent_id
        .map(|id| format!("  <AgentID>{}</AgentID>\n", id))
        .unwrap_or_default();

    format!(
        r#"<xml>
  <ToUserName><![CDATA[{}]]></ToUserName>
  <FromUserName><![CDATA[{}]]></FromUserName>
  <CreateTime>{}</CreateTime>
  <MsgType><![CDATA[text]]></MsgType>
  <Content><![CDATA[{}]]></Content>
{}</xml>"#,
        to_user, from_user, timestamp, content, agent_xml
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
        assert!(!response.contains("<AgentID>"));
    }

    #[test]
    fn test_build_wecom_response_with_agent_id() {
        let response = build_wecom_response("ww_corp", "zhangsan", Some(1000002), "Hello!");
        assert!(response.contains("<ToUserName><![CDATA[ww_corp]]></ToUserName>"));
        assert!(response.contains("<FromUserName><![CDATA[zhangsan]]></FromUserName>"));
        assert!(response.contains("<Content><![CDATA[Hello!]]></Content>"));
        assert!(response.contains("<AgentID>1000002</AgentID>"));
    }

    #[test]
    fn test_build_wecom_response_without_agent_id() {
        let response = build_wecom_response("ww_corp", "zhangsan", None, "Hello!");
        assert!(response.contains("<ToUserName><![CDATA[ww_corp]]></ToUserName>"));
        assert!(!response.contains("<AgentID>"));
    }
}
