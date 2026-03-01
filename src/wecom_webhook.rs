//! WeCom (企业微信) webhook handler
//!
//! Handles webhook callbacks from WeCom platform:
//! - GET request: URL verification during setup
//! - POST request: Receive messages from WeCom users

use axum::{
    Router,
    extract::{Query, State},
    http::StatusCode,
    routing::get,
};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::time::timeout;
use tracing::{debug, error, info, warn};

use crate::broker::MessageBroker;
use crate::config::ProxyConfig;
use crate::crypto::WechatCrypto;
use crate::types::{WecomEncryptedBody, WecomEncryptedParams, WecomMessage, WecomVerifyParams};

/// WeCom webhook server state
#[derive(Clone)]
pub struct WecomWebhookState {
    pub config: ProxyConfig,
    pub broker: Arc<MessageBroker>,
    pub crypto: Option<WechatCrypto>,
}

/// Run the WeCom webhook HTTP server
pub async fn run_server(addr: SocketAddr, broker: Arc<MessageBroker>) -> anyhow::Result<()> {
    let config = broker.config.clone();

    // Create crypto if WeCom encryption is configured
    let crypto = match (&config.wecom_encoding_aes_key, &config.wecom_corp_id) {
        (Some(key), Some(corp_id)) => {
            info!(
                "WeCom encryption enabled, key_len={}, corp_id={}",
                key.len(),
                corp_id
            );
            match WechatCrypto::new(key, corp_id) {
                Ok(c) => Some(c),
                Err(e) => {
                    error!("Failed to create WeCom crypto: {}", e);
                    return Err(e);
                }
            }
        }
        _ => {
            warn!("WeCom encryption not configured, running in plain mode");
            None
        }
    };

    let state = WecomWebhookState {
        config,
        broker,
        crypto,
    };

    let app = Router::new()
        // WeCom webhook endpoint
        .route("/wecom/callback", get(verify_url).post(handle_message))
        .route("/health", get(health_check))
        .with_state(state);

    info!("🔌 WeCom webhook server starting on {}", addr);
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}

/// Health check endpoint
async fn health_check() -> &'static str {
    "OK"
}

/// Handle WeCom URL verification (GET request)
///
/// When setting up the webhook in WeCom admin console, WeCom sends a GET
/// request with encrypted echostr. We must decrypt it and return the plaintext.
async fn verify_url(
    Query(params): Query<WecomVerifyParams>,
    State(state): State<WecomWebhookState>,
) -> Result<String, StatusCode> {
    debug!(
        "WeCom URL verification: msg_signature={}, timestamp={}, nonce={}, echostr_len={}",
        params.msg_signature,
        params.timestamp,
        params.nonce,
        params.echostr.len()
    );

    let token = state
        .config
        .wecom_token
        .as_ref()
        .ok_or(StatusCode::BAD_REQUEST)?;

    // Verify signature: msg_signature = SHA1(sort(token, timestamp, nonce, echostr))
    // This is DIFFERENT from the basic sign() which only uses token, timestamp, nonce
    let is_valid = WechatCrypto::verify_message(
        token,
        &params.timestamp,
        &params.nonce,
        &params.echostr,
        &params.msg_signature,
    );

    if !is_valid {
        warn!(
            "WeCom URL signature verification failed: expected_signature={}, token={}",
            params.msg_signature, token
        );
        return Err(StatusCode::UNAUTHORIZED);
    }

    // Decrypt echostr to get verification string
    if let Some(crypto) = &state.crypto {
        match crypto.decrypt(&params.echostr) {
            Ok(decrypted) => {
                info!(
                    "WeCom URL verification successful, decrypted_len={}",
                    decrypted.len()
                );
                // Return decrypted content (must be exact, no quotes)
                // Content-Type is automatically text/plain for String return type
                Ok(decrypted)
            }
            Err(e) => {
                error!("Failed to decrypt WeCom echostr: {}", e);
                Err(StatusCode::BAD_REQUEST)
            }
        }
    } else {
        // Plain mode - return echostr as-is
        info!("WeCom URL verification successful (plain mode)");
        Ok(params.echostr)
    }
}

/// Handle WeCom message (POST request)
///
/// Receives encrypted message from WeCom, decrypts it, and forwards to UGENT
async fn handle_message(
    Query(params): Query<WecomEncryptedParams>,
    State(state): State<WecomWebhookState>,
    body: String,
) -> Result<String, StatusCode> {
    debug!(
        "WeCom message received: msg_signature={}, timestamp={}, nonce={}",
        params.msg_signature, params.timestamp, params.nonce
    );

    if state.config.debug_mode {
        debug!("WeCom raw request body: {}", body);
    }

    // Parse encrypted message body
    let encrypted: WecomEncryptedBody = serde_xml_rs::from_str(&body).map_err(|e| {
        error!("Failed to parse WeCom encrypted message: {}", e);
        StatusCode::BAD_REQUEST
    })?;

    let token = state
        .config
        .wecom_token
        .as_ref()
        .ok_or(StatusCode::BAD_REQUEST)?;

    // Verify signature: msg_signature = SHA1(sort(token, timestamp, nonce, encrypted_msg))
    // This is DIFFERENT from basic sign() which only uses token, timestamp, nonce
    let is_valid = WechatCrypto::verify_message(
        token,
        &params.timestamp,
        &params.nonce,
        &encrypted.encrypt,
        &params.msg_signature,
    );

    if !is_valid {
        warn!(
            "WeCom message signature verification failed: msg_signature={}",
            params.msg_signature
        );
        return Err(StatusCode::UNAUTHORIZED);
    }

    // Decrypt message
    let decrypted_content = if let Some(crypto) = &state.crypto {
        crypto.decrypt(&encrypted.encrypt).map_err(|e| {
            error!("Failed to decrypt WeCom message: {}", e);
            StatusCode::BAD_REQUEST
        })?
    } else {
        // Plain mode - use encrypt field as content (base64 decoded)
        encrypted.encrypt
    };

    if state.config.debug_mode {
        debug!("WeCom decrypted message: {}", decrypted_content);
    }

    // Parse WeCom message
    let message: WecomMessage = serde_xml_rs::from_str(&decrypted_content).map_err(|e| {
        error!("Failed to parse WeCom message XML: {}", e);
        StatusCode::BAD_REQUEST
    })?;

    info!(
        "Received WeCom message from user {} (AgentID: {:?}): {:?}",
        message.from_user_name.as_deref().unwrap_or("unknown"),
        message.agent_id,
        message.content
    );

    // Handle kf_msg_or_event - need to fetch actual message via sync_msg API
    if message.event.as_deref() == Some("kf_msg_or_event")
        && let (Some(token), Some(open_kfid)) = (&message.kf_token, &message.open_kfid)
    {
        info!("Received kf_msg_or_event, calling sync_msg API with token");

        // Get KF API client from broker
        if let Some(kf_client) = &state.broker.kf_api {
            match kf_client.sync_kf_messages(token, open_kfid).await {
                Ok(sync_response) => {
                    info!("Synced KF messages, has_more={:?}", sync_response.has_more);
                    if let Some(msg_list) = sync_response.msg_list {
                        info!("Processing {} KF messages", msg_list.len());
                        
                        // Bug fix: Only process the LATEST message (last in list, or highest send_time)
                        // sync_msg returns messages from oldest to newest
                        let latest_msg = msg_list.into_iter().rev().find(|m| {
                            // Find the latest customer message (origin=3) with text content
                            m.msgtype == "text" && m.origin == Some(3) && m.text.is_some()
                        });
                        
                        if let Some(kf_msg) = latest_msg {
                            info!(
                                "Processing LATEST KF message: msgid={}, msgtype={}, external_user={:?}, send_time={}",
                                kf_msg.msgid, kf_msg.msgtype, kf_msg.external_userid, kf_msg.send_time
                            );

                            let text = kf_msg.text.as_ref().unwrap();
                            let external_user = kf_msg.external_userid.clone().unwrap_or_else(|| "unknown".to_string());
                            let msg_open_kfid = kf_msg.open_kfid.clone().unwrap_or_else(|| open_kfid.clone());
                            
                            // Build WecomMessage from KF message
                            let kf_message = WecomMessage {
                                to_user_name: message.to_user_name.clone(),
                                from_user_name: Some(external_user.clone()),
                                create_time: Some(kf_msg.send_time as i64),
                                msg_type: Some("text".to_string()),
                                content: Some(text.content.clone()),
                                msg_id: None, // KF msgid is string, WecomMessage expects i64
                                agent_id: None,
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
                                kf_token: Some(token.to_string()), // Store token for reply
                                open_kfid: Some(msg_open_kfid.clone()),
                                kf_msg_id: Some(kf_msg.msgid.clone()), // KF message ID for dedup
                            };

                            info!(
                                "Forwarding KF text message from {}: {}",
                                external_user, text.content
                            );

                            // Use fire-and-forget pattern for KF messages
                            // WeCom expects immediate "success" response, reply comes via KF API
                            let broker = state.broker.clone();
                            let _body = body.clone();
                            tokio::spawn(async move {
                                // This will return immediately for KF messages
                                // Response will be sent via KF API when LLM completes
                                match broker.forward_wecom_message(kf_message, _body).await {
                                    Ok(response) => {
                                        debug!("KF message forwarded successfully: {}", response);
                                    }
                                    Err(e) => {
                                        warn!("Failed to forward KF message: {}", e);
                                    }
                                }
                            });
                        }
                    }
                }
                Err(e) => {
                    warn!("Failed to sync KF messages: {}", e);
                }
            }
        } else {
            warn!("KF API client not configured, cannot fetch KF message content");
        }

        // Return success immediately for KF events (WeCom expects quick response)
        return Ok("success".to_string());
    }

    // Forward to broker and wait for response
    let response_timeout = Duration::from_secs(state.config.message_timeout_secs);

    match timeout(
        response_timeout,
        state.broker.forward_wecom_message(message, body),
    )
    .await
    {
        Ok(Ok(response)) => {
            info!("Got response from UGENT for WeCom message");
            Ok(response)
        }
        Ok(Err(e)) => {
            error!("Error from broker for WeCom message: {}", e);
            // Return success to WeCom, send async message later via API
            Ok("success".to_string())
        }
        Err(_) => {
            warn!("Timeout waiting for UGENT response for WeCom message");
            // Return success to WeCom, will use application message API for async reply
            Ok("success".to_string())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wecom_verify_params_parsing() {
        let query = "msg_signature=abc123&timestamp=1234567890&nonce=xyz789&echostr=encrypted_str";
        let params: WecomVerifyParams = serde_urlencoded::from_str(query).unwrap();
        assert_eq!(params.msg_signature, "abc123");
        assert_eq!(params.timestamp, "1234567890");
        assert_eq!(params.nonce, "xyz789");
        assert_eq!(params.echostr, "encrypted_str");
    }

    #[test]
    fn test_wecom_encrypted_body_parsing() {
        let xml = r#"<xml>
            <ToUserName><![CDATA[ww1234567890abcdef]]></ToUserName>
            <AgentID>1000002</AgentID>
            <Encrypt><![CDATA[encrypted_content_here]]></Encrypt>
        </xml>"#;

        let body: WecomEncryptedBody = serde_xml_rs::from_str(xml).unwrap();
        assert_eq!(body.to_user_name, "ww1234567890abcdef");
        assert_eq!(body.agent_id, Some("1000002".to_string()));
        assert_eq!(body.encrypt, "encrypted_content_here");
    }
}
