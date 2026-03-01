//! WeCom (企业微信) webhook handler
//!
//! Handles webhook callbacks from WeCom platform:
//! - GET request: URL verification during setup
//! - POST request: Receive messages from WeCom users
#![allow(clippy::too_many_arguments)]

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
use crate::storage::MessageStore;
use crate::types::{WecomEncryptedBody, WecomEncryptedParams, WecomMessage, WecomVerifyParams};

/// WeCom webhook server state
#[derive(Clone)]
pub struct WecomWebhookState {
    pub config: ProxyConfig,
    pub broker: Arc<MessageBroker>,
    pub crypto: Option<WechatCrypto>,
    pub storage: Option<Arc<MessageStore>>,
}

/// Run the WeCom webhook HTTP server
pub async fn run_server(
    addr: SocketAddr,
    broker: Arc<MessageBroker>,
    storage: Option<Arc<MessageStore>>,
) -> anyhow::Result<()> {
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
        storage,
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
                    if let Some(ref msg_list) = sync_response.msg_list {
                        info!("Processing {} KF messages", msg_list.len());

                        // Debug: log all messages with their types and origins
                        for (idx, m) in msg_list.iter().enumerate() {
                            debug!(
                                "KF msg[{}]: msgid={}, msgtype={}, origin={:?}, external_user={:?}, send_time={}, has_text={}, has_image={}, has_voice={}",
                                idx,
                                m.msgid,
                                m.msgtype,
                                m.origin,
                                m.external_userid,
                                m.send_time,
                                m.text.is_some(),
                                m.image.is_some(),
                                m.voice.is_some()
                            );
                        }

                        // Bug fix: Only process the LATEST message (last in list, or highest send_time)
                        // sync_msg returns messages from oldest to newest
                        let latest_msg = msg_list.iter().rev().find(|m| {
                            // Find the latest customer message (origin=3) with any content type
                            m.origin == Some(3)
                                && ((m.msgtype == "text" && m.text.is_some())
                                    || (m.msgtype == "image" && m.image.is_some())
                                    || (m.msgtype == "voice" && m.voice.is_some()))
                        });

                        if let Some(kf_msg) = latest_msg {
                            info!(
                                "Processing LATEST KF message: msgid={}, msgtype={}, external_user={:?}, send_time={}",
                                kf_msg.msgid,
                                kf_msg.msgtype,
                                kf_msg.external_userid,
                                kf_msg.send_time
                            );

                            let external_user = kf_msg
                                .external_userid
                                .clone()
                                .unwrap_or_else(|| "unknown".to_string());
                            let msg_open_kfid = kf_msg
                                .open_kfid
                                .clone()
                                .unwrap_or_else(|| open_kfid.clone());

                            // Process based on message type
                            match kf_msg.msgtype.as_str() {
                                "text" => {
                                    let text = kf_msg.text.as_ref().unwrap();
                                    process_kf_text_message(
                                        &state,
                                        &message,
                                        kf_msg,
                                        &body,
                                        &external_user,
                                        &msg_open_kfid,
                                        token,
                                        &text.content,
                                        &sync_response,
                                    )
                                    .await;
                                }
                                "image" => {
                                    let image = kf_msg.image.as_ref().unwrap();
                                    info!(
                                        "Processing image message: media_id={:?}, cos_url={:?}, file_size={:?}",
                                        image.media_id, image.cos_url, image.file_size
                                    );

                                    // Clone necessary data for background processing
                                    let state_clone = state.clone();
                                    let message_clone = message.clone();
                                    let kf_msg_clone = kf_msg.clone();
                                    let body_clone = body.to_string();
                                    let external_user_clone = external_user.to_string();
                                    let msg_open_kfid_clone = msg_open_kfid.to_string();
                                    let token_clone = token.to_string();
                                    let media_id_clone = image.media_id.clone();

                                    // Spawn background task to download and process image
                                    tokio::spawn(async move {
                                        process_kf_image_message_spawned(
                                            &state_clone,
                                            &message_clone,
                                            &kf_msg_clone,
                                            &body_clone,
                                            &external_user_clone,
                                            &msg_open_kfid_clone,
                                            &token_clone,
                                            &media_id_clone,
                                        )
                                        .await;
                                    });
                                    info!(
                                        "Spawned background task for image download: media_id={}",
                                        image.media_id
                                    );
                                }
                                "voice" => {
                                    let voice = kf_msg.voice.as_ref().unwrap();
                                    process_kf_voice_message(
                                        &state,
                                        &message,
                                        kf_msg,
                                        &body,
                                        &external_user,
                                        &msg_open_kfid,
                                        token,
                                        &voice.media_id,
                                        &sync_response,
                                    )
                                    .await;
                                }
                                _ => {
                                    warn!("Unsupported KF message type: {}", kf_msg.msgtype);
                                }
                            }
                            return Ok("success".to_string());
                        } else {
                            warn!(
                                "No matching KF message found (origin=3 with text/image/voice content)"
                            );
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

// ============================================================================
// KF Message Processing Helper Functions
// ============================================================================

use std::path::PathBuf;

use crate::media_cache::MediaCache;
use crate::types::MediaContent;
use crate::wecom_api::KfMessage;
use base64::{Engine, engine::general_purpose::STANDARD as BASE64};

/// Process KF text message
async fn process_kf_text_message(
    state: &WecomWebhookState,
    original_message: &WecomMessage,
    kf_msg: &KfMessage,
    body: &str,
    external_user: &str,
    msg_open_kfid: &str,
    token: &str,
    text_content: &str,
    sync_response: &crate::wecom_api::KfSyncMsgResponse,
) {
    // Build WecomMessage from KF message
    let kf_message = WecomMessage {
        to_user_name: original_message.to_user_name.clone(),
        from_user_name: Some(external_user.to_string()),
        create_time: Some(kf_msg.send_time as i64),
        msg_type: Some("text".to_string()),
        content: Some(text_content.to_string()),
        msg_id: None,
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
        kf_token: Some(token.to_string()),
        open_kfid: Some(msg_open_kfid.to_string()),
        kf_msg_id: Some(kf_msg.msgid.clone()),
    };

    info!(
        "Forwarding KF text message from {}: {}",
        external_user, text_content
    );

    // Save message to storage
    save_kf_message_to_storage(
        state,
        kf_msg,
        msg_open_kfid,
        external_user,
        "text",
        Some(text_content),
        sync_response,
    );

    // Forward to broker
    forward_kf_message_to_broker(&state.broker, kf_message, body.to_string());
}

/// Process KF image message in background (spawned task)
/// This allows the webhook to return success immediately while downloading the image
async fn process_kf_image_message_spawned(
    state: &WecomWebhookState,
    original_message: &WecomMessage,
    kf_msg: &KfMessage,
    body: &str,
    external_user: &str,
    msg_open_kfid: &str,
    token: &str,
    media_id: &str,
) {
    info!("Background processing image message: media_id={}", media_id);

    // Download image from WeCom with timeout
    let image_data = match tokio::time::timeout(
        std::time::Duration::from_secs(30),
        download_media(state, media_id),
    )
    .await
    {
        Ok(Some(data)) => data,
        Ok(None) => {
            warn!("Failed to download image media_id={}", media_id);
            return;
        }
        Err(_) => {
            warn!("Timeout downloading image media_id={}", media_id);
            return;
        }
    };

    info!("Downloaded image {} ({} bytes)", media_id, image_data.len());

    // Save to cache and get local path
    let cache = MediaCache::new(&state.config.media_cache_dir);
    let local_path: PathBuf = match cache.save(media_id, "image", &image_data).await {
        Ok(path) => path,
        Err(e) => {
            warn!("Failed to cache image: {}", e);
            return;
        }
    };

    // Encode as base64
    let base64_data = BASE64.encode(&image_data);

    // Build WecomMessage from KF message
    let kf_message = WecomMessage {
        to_user_name: original_message.to_user_name.clone(),
        from_user_name: Some(external_user.to_string()),
        create_time: Some(kf_msg.send_time as i64),
        msg_type: Some("image".to_string()),
        content: None,
        msg_id: None,
        agent_id: None,
        pic_url: None,
        media_id: Some(media_id.to_string()),
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
        kf_token: Some(token.to_string()),
        open_kfid: Some(msg_open_kfid.to_string()),
        kf_msg_id: Some(kf_msg.msgid.clone()),
    };

    info!(
        "Forwarding KF image message from {}: media_id={}, local_path={:?}",
        external_user, media_id, local_path
    );

    // Forward to broker with media content
    let media_content = MediaContent::Image {
        media_id: media_id.to_string(),
        local_path: Some(local_path.to_string_lossy().to_string()),
        data: Some(base64_data),
    };
    forward_kf_media_message_to_broker(&state.broker, kf_message, body.to_string(), media_content);
    info!("Image message processing completed: media_id={}", media_id);
}

/// Process KF voice message
async fn process_kf_voice_message(
    state: &WecomWebhookState,
    original_message: &WecomMessage,
    kf_msg: &KfMessage,
    body: &str,
    external_user: &str,
    msg_open_kfid: &str,
    token: &str,
    media_id: &str,
    sync_response: &crate::wecom_api::KfSyncMsgResponse,
) {
    // Download voice from WeCom
    let voice_data = match download_media(state, media_id).await {
        Some(data) => data,
        None => {
            warn!("Failed to download voice media_id={}", media_id);
            return;
        }
    };

    // Save to cache and get local path
    let cache = MediaCache::new(&state.config.media_cache_dir);
    let local_path: PathBuf = match cache.save(media_id, "voice", &voice_data).await {
        Ok(path) => path,
        Err(e) => {
            warn!("Failed to cache voice: {}", e);
            return;
        }
    };

    // Encode as base64
    let base64_data = BASE64.encode(&voice_data);

    // Build WecomMessage from KF message
    let kf_message = WecomMessage {
        to_user_name: original_message.to_user_name.clone(),
        from_user_name: Some(external_user.to_string()),
        create_time: Some(kf_msg.send_time as i64),
        msg_type: Some("voice".to_string()),
        content: None,
        msg_id: None,
        agent_id: None,
        pic_url: None,
        media_id: Some(media_id.to_string()),
        format: Some("amr".to_string()),
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
        kf_token: Some(token.to_string()),
        open_kfid: Some(msg_open_kfid.to_string()),
        kf_msg_id: Some(kf_msg.msgid.clone()),
    };

    info!(
        "Forwarding KF voice message from {}: media_id={}, local_path={:?}",
        external_user, media_id, local_path
    );

    // Save message to storage
    save_kf_message_to_storage(
        state,
        kf_msg,
        msg_open_kfid,
        external_user,
        "voice",
        None,
        sync_response,
    );

    // Forward to broker with media content
    let media_content = MediaContent::Voice {
        media_id: media_id.to_string(),
        local_path: Some(local_path.to_string_lossy().to_string()),
        data: Some(base64_data),
        format: Some("amr".to_string()),
    };
    forward_kf_media_message_to_broker(&state.broker, kf_message, body.to_string(), media_content);
}

/// Download media from WeCom
async fn download_media(state: &WecomWebhookState, media_id: &str) -> Option<Vec<u8>> {
    if let Some(kf_client) = &state.broker.kf_api {
        match kf_client.get_media(media_id).await {
            Ok(data) => {
                info!("Downloaded media {} ({} bytes)", media_id, data.len());
                Some(data)
            }
            Err(e) => {
                warn!("Failed to download media {}: {}", media_id, e);
                None
            }
        }
    } else {
        warn!("KF API client not available for media download");
        None
    }
}

/// Save KF message to storage
fn save_kf_message_to_storage(
    state: &WecomWebhookState,
    kf_msg: &KfMessage,
    msg_open_kfid: &str,
    external_user: &str,
    msg_type: &str,
    content: Option<&str>,
    sync_response: &crate::wecom_api::KfSyncMsgResponse,
) {
    if let Some(storage) = &state.storage {
        use crate::storage::KfMessage as StoredKfMessage;
        let stored_msg = StoredKfMessage::new(
            kf_msg.msgid.clone(),
            msg_open_kfid.to_string(),
            external_user.to_string(),
            msg_type.to_string(),
            content.map(|s| s.to_string()),
            Some(3),
            kf_msg.send_time as i64,
        );
        match storage.save_message(&stored_msg) {
            Ok(true) => debug!("Saved KF message to storage"),
            Ok(false) => {
                info!(
                    "KF message {} already in storage, skipping duplicate",
                    kf_msg.msgid
                );
            }
            Err(e) => warn!("Failed to save KF message: {}", e),
        }

        // Update sync cursor
        if let Some(cursor) = &sync_response.next_cursor {
            debug!("Got sync cursor: {}", cursor);
        }

        // Note: conversation tracking handled by message dedup
        let _ = (msg_open_kfid, external_user, &kf_msg.msgid);
    }
}

/// Forward KF text message to broker (fire-and-forget)
fn forward_kf_message_to_broker(
    broker: &Arc<MessageBroker>,
    kf_message: WecomMessage,
    body: String,
) {
    let broker = broker.clone();
    tokio::spawn(async move {
        match broker.forward_wecom_message(kf_message, body).await {
            Ok(response) => {
                debug!("KF message forwarded successfully: {}", response);
            }
            Err(e) => {
                warn!("Failed to forward KF message: {}", e);
            }
        }
    });
}

/// Forward KF media message to broker (fire-and-forget)
fn forward_kf_media_message_to_broker(
    broker: &Arc<MessageBroker>,
    kf_message: WecomMessage,
    body: String,
    media_content: MediaContent,
) {
    let broker = broker.clone();
    tokio::spawn(async move {
        match broker
            .forward_wecom_media_message(kf_message, body, media_content)
            .await
        {
            Ok(response) => {
                debug!("KF media message forwarded successfully: {}", response);
            }
            Err(e) => {
                warn!("Failed to forward KF media message: {}", e);
            }
        }
    });
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
            <Encrypt><![CDATA[encrypted_content_here]]></Encrypt>
        </xml>"#;

        let body: WecomEncryptedBody = serde_xml_rs::from_str(xml).unwrap();
        assert_eq!(body.encrypt, "encrypted_content_here");
    }
}
