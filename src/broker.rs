//! Message broker - connects webhook handlers to WebSocket clients

use anyhow::{Result, anyhow};
use dashmap::DashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::oneshot;
use tracing::{debug, info, warn};
use uuid::Uuid;

use crate::config::ProxyConfig;
use crate::types::{ProxyMessage, WechatMessage};

/// Pending response tracker
struct PendingResponse {
    tx: oneshot::Sender<String>,
    created_at: std::time::Instant,
}

/// Message broker state
pub struct MessageBroker {
    pub config: ProxyConfig,
    /// Pending responses: message_id -> response channel
    pending: Arc<DashMap<Uuid, PendingResponse>>,
    /// Default client ID for routing (first connected client)
    default_client: Arc<parking_lot::RwLock<Option<String>>>,
}

impl MessageBroker {
    pub fn new(config: ProxyConfig) -> Self {
        Self {
            config,
            pending: Arc::new(DashMap::new()),
            default_client: Arc::new(parking_lot::RwLock::new(None)),
        }
    }

    /// Forward message from WeChat to UGENT and wait for response
    pub async fn forward_message(&self, message: WechatMessage, raw_xml: String) -> Result<String> {
        // Get target client
        let client_id = self.get_target_client()?;

        // Create proxy message
        let proxy_msg = ProxyMessage::inbound(&client_id, message.clone(), raw_xml);

        // Create response channel
        let (tx, rx) = oneshot::channel();

        // Register pending response
        self.pending.insert(
            proxy_msg.id,
            PendingResponse {
                tx,
                created_at: std::time::Instant::now(),
            },
        );

        // Clean up old pending responses
        self.cleanup_old_pending();

        debug!(
            "Forwarding message {} to client {}",
            proxy_msg.id, client_id
        );

        // Note: In real implementation, this would send via WebSocketManager
        // For now, we'll handle this through the response mechanism

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
            // Build WeChat response XML
            // Note: In real implementation, we'd have the original message to get from_user_name
            let response_xml = content; // For now, pass through

            if pending.tx.send(response_xml).is_err() {
                warn!("Failed to send response - channel closed");
            }
        } else {
            warn!("No pending response found for message {}", original_id);
        }

        Ok(())
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
