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
            info!("WeCom encryption enabled");
            Some(WechatCrypto::new(key, corp_id)?)
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
        "WeCom URL verification: signature={}, timestamp={}, nonce={}",
        params.msg_signature, params.timestamp, params.nonce
    );

    let token = state
        .config
        .wecom_token
        .as_ref()
        .ok_or(StatusCode::BAD_REQUEST)?;

    // Verify signature using token
    let signature = WechatCrypto::sign(token, &params.timestamp, &params.nonce);

    if signature != params.msg_signature {
        warn!("WeCom signature verification failed");
        return Err(StatusCode::UNAUTHORIZED);
    }

    // Decrypt echostr to get verification string
    if let Some(crypto) = &state.crypto {
        match crypto.decrypt(&params.echostr) {
            Ok(decrypted) => {
                info!("WeCom URL verification successful");
                // Return decrypted content (must be exact, no quotes)
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

    // Verify signature
    let signature = WechatCrypto::sign(token, &params.timestamp, &params.nonce);

    if signature != params.msg_signature {
        warn!("WeCom message signature verification failed");
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
        message.from_user_name, message.agent_id, message.content
    );

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
        assert_eq!(body.agent_id, Some(1000002));
        assert_eq!(body.encrypt, "encrypted_content_here");
    }
}
