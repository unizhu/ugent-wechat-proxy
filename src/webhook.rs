//! WeChat webhook HTTP handlers

use axum::{
    Router,
    body::{Body, Bytes},
    extract::{Query, State},
    http::{Request, StatusCode},
    middleware::{self, Next},
    response::Response,
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
use crate::types::*;

/// Webhook server state
#[derive(Clone)]
pub struct WebhookState {
    pub config: ProxyConfig,
    pub broker: Arc<MessageBroker>,
    pub crypto: Option<WechatCrypto>,
}

/// Run the webhook HTTP server
pub async fn run_server(addr: SocketAddr, broker: Arc<MessageBroker>) -> anyhow::Result<()> {
    let config = broker.config.clone();

    let crypto = match (&config.wechat_encoding_aes_key, &config.wechat_app_id) {
        (Some(key), Some(app_id)) => Some(WechatCrypto::new(key, app_id)?),
        _ => None,
    };

    let state = WebhookState {
        config,
        broker,
        crypto,
    };

    let app = Router::new()
        // WeChat webhook endpoint
        .route("/wechat/webhook", get(verify).post(handle_message))
        .route("/health", get(health_check))
        .layer(middleware::from_fn(log_request))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}

/// Health check endpoint
async fn health_check() -> &'static str {
    "OK"
}

/// Middleware to log all incoming HTTP requests
async fn log_request(req: Request<Body>, next: Next) -> Response {
    let method = req.method().clone();
    let uri = req.uri().clone();
    let query = uri.query().map(|q| format!("?{}", q)).unwrap_or_default();

    info!("🌐 HTTP {} {}{}", method, uri.path(), query);

    let response = next.run(req).await;

    info!("📤 Response status: {}", response.status());

    response
}

/// Webhook verification (GET request from WeChat)
async fn verify(
    State(state): State<WebhookState>,
    Query(params): Query<VerifyParams>,
) -> Result<String, StatusCode> {
    info!(
        "📥 Received verification request from WeChat: timestamp={}, nonce={}, signature={}",
        params.timestamp, params.nonce, params.signature
    );

    if !WechatCrypto::verify(
        &state.config.wechat_token,
        &params.timestamp,
        &params.nonce,
        &params.signature,
    ) {
        warn!("Invalid signature in verification request");
        return Err(StatusCode::FORBIDDEN);
    }

    info!("Webhook verification successful");
    Ok(params.echostr)
}

/// Handle incoming message (POST request from WeChat)
async fn handle_message(
    State(state): State<WebhookState>,
    Query(params): Query<EncryptedParams>,
    body: Bytes,
) -> Result<String, StatusCode> {
    info!(
        "📥 Received message from WeChat: timestamp={}, nonce={}, signature={}, encrypt_type={:?}",
        params.timestamp, params.nonce, params.signature, params.encrypt_type
    );
    debug!("Request body length: {} bytes", body.len());

    // Verify signature
    if !WechatCrypto::verify(
        &state.config.wechat_token,
        &params.timestamp,
        &params.nonce,
        &params.signature,
    ) {
        warn!("Invalid signature in message request");
        return Err(StatusCode::FORBIDDEN);
    }

    // Decrypt if needed
    let xml_content = if params.encrypt_type.as_deref() == Some("aes") {
        let encrypted: EncryptedMessage = match serde_xml_rs::from_reader(&*body) {
            Ok(msg) => msg,
            Err(e) => {
                error!("Failed to parse encrypted message: {}", e);
                return Err(StatusCode::BAD_REQUEST);
            }
        };

        // Verify message signature
        if let (Some(msg_signature), Some(_crypto)) = (&params.msg_signature, &state.crypto)
            && !WechatCrypto::verify_message(
                &state.config.wechat_token,
                &params.timestamp,
                &params.nonce,
                &encrypted.encrypt,
                msg_signature,
            )
        {
            warn!("Invalid message signature");
            return Err(StatusCode::FORBIDDEN);
        }

        match &state.crypto {
            Some(crypto) => match crypto.decrypt(&encrypted.encrypt) {
                Ok(decrypted) => decrypted,
                Err(e) => {
                    error!("Failed to decrypt message: {}", e);
                    return Err(StatusCode::INTERNAL_SERVER_ERROR);
                }
            },
            None => {
                error!("Received encrypted message but no crypto configured");
                return Err(StatusCode::INTERNAL_SERVER_ERROR);
            }
        }
    } else {
        String::from_utf8_lossy(&body).to_string()
    };

    if state.config.debug_mode {
        debug!("Raw XML content: {}", xml_content);
    }

    // Parse message
    let message: WechatMessage = match serde_xml_rs::from_str(&xml_content) {
        Ok(msg) => msg,
        Err(e) => {
            error!("Failed to parse message XML: {}", e);
            return Err(StatusCode::BAD_REQUEST);
        }
    };

    info!(
        "Received {} message from user {}",
        serde_json::to_string(&message.msg_type).unwrap_or_default(),
        message.from_user_name
    );

    // Forward to UGENT via broker and wait for response
    let response_timeout = Duration::from_secs(state.config.message_timeout_secs);

    match timeout(
        response_timeout,
        state.broker.forward_message(message, xml_content),
    )
    .await
    {
        Ok(Ok(response)) => {
            info!("Got response from UGENT");
            Ok(response)
        }
        Ok(Err(e)) => {
            error!("Error from broker: {}", e);
            // Return success to WeChat, send async later
            Ok("success".to_string())
        }
        Err(_) => {
            warn!("Timeout waiting for UGENT response");
            // Return success to WeChat, will use customer service API for async reply
            Ok("success".to_string())
        }
    }
}
