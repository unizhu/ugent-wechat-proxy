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
use crate::crypto::{self, WechatCrypto, is_timestamp_fresh};
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

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, build_router(state)).await?;

    Ok(())
}

/// Build the OA webhook router.
///
/// Split out from `run_server` so tests can drive the real handlers without
/// binding a port.
pub fn build_router(state: WebhookState) -> Router {
    Router::new()
        .route("/wechat/webhook", get(verify).post(handle_message))
        .route("/health", get(health_check))
        .layer(middleware::from_fn(log_request))
        .with_state(state)
}

/// Health check endpoint
async fn health_check() -> &'static str {
    "OK"
}

/// Middleware to log all incoming HTTP requests
async fn log_request(req: Request<Body>, next: Next) -> Response {
    let method = req.method().clone();
    let uri = req.uri().clone();

    // The query carries signature/msg_signature/timestamp/nonce. Those are only
    // good for the freshness window, but there is no reason to persist a valid
    // signature triple to the log store.
    info!("🌐 HTTP {} {}", method, uri.path());

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

    if !is_timestamp_fresh(&params.timestamp, crypto::TIMESTAMP_TOLERANCE_SECS) {
        warn!("Stale timestamp in verification request");
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

    // Outer gate. Note this digest covers only (token, timestamp, nonce) — it
    // says nothing about the body, so it cannot be the only check on a POST.
    if !WechatCrypto::verify(
        &state.config.wechat_token,
        &params.timestamp,
        &params.nonce,
        &params.signature,
    ) {
        warn!("Invalid signature in message request");
        return Err(StatusCode::FORBIDDEN);
    }

    // Without this, one observed (timestamp, nonce, signature) triple authorizes
    // arbitrary POSTs forever, because none of the three depends on the body.
    if !is_timestamp_fresh(&params.timestamp, crypto::TIMESTAMP_TOLERANCE_SECS) {
        warn!("Stale timestamp in message request");
        return Err(StatusCode::FORBIDDEN);
    }

    let xml_content = if params.encrypt_type.as_deref() == Some("aes") {
        let encrypted: EncryptedMessage = match serde_xml_rs::from_reader(&*body) {
            Ok(msg) => msg,
            Err(e) => {
                error!("Failed to parse encrypted message: {}", e);
                return Err(StatusCode::BAD_REQUEST);
            }
        };

        // msg_signature is what actually binds the request to its body. It is
        // mandatory: skipping it when absent would make the binding opt-in for
        // the caller.
        let Some(msg_signature) = params.msg_signature.as_deref() else {
            warn!("Encrypted message is missing msg_signature");
            return Err(StatusCode::FORBIDDEN);
        };

        let Some(crypto) = state.crypto.as_ref() else {
            error!("Received encrypted message but no crypto configured");
            return Err(StatusCode::INTERNAL_SERVER_ERROR);
        };

        if !WechatCrypto::verify_message(
            &state.config.wechat_token,
            &params.timestamp,
            &params.nonce,
            &encrypted.encrypt,
            msg_signature,
        ) {
            warn!("Invalid message signature");
            return Err(StatusCode::FORBIDDEN);
        }

        match crypto.decrypt(&encrypted.encrypt) {
            Ok(decrypted) => decrypted,
            Err(e) => {
                error!("Failed to decrypt message: {}", e);
                return Err(StatusCode::INTERNAL_SERVER_ERROR);
            }
        }
    } else if state.config.allow_plaintext_webhook {
        // 明文模式. Legitimate, but nothing signs the body in this mode, so any
        // replayed signature triple carries an attacker-chosen message.
        String::from_utf8_lossy(&body).to_string()
    } else {
        warn!(
            "Rejected a plaintext webhook POST — the Official Account should be in \
             safe mode (安全模式). Set WECHAT_ALLOW_PLAINTEXT_WEBHOOK=true to accept \
             unencrypted callbacks anyway."
        );
        return Err(StatusCode::FORBIDDEN);
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

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request as HttpRequest;
    use tower::ServiceExt;

    const TOKEN: &str = "test-token";

    /// Build a config with only the fields these tests care about.
    ///
    /// Deserialized rather than written as a struct literal so that adding an
    /// unrelated field with a serde default does not break every test here.
    fn config(allow_plaintext: bool) -> ProxyConfig {
        serde_json::from_value(serde_json::json!({
            "wechat_token": TOKEN,
            "wechat_encoding_aes_key": null,
            "wechat_app_id": null,
            "wechat_app_secret": null,
            "template_id_response_ready": null,
            "allow_plaintext_webhook": allow_plaintext,
            "wecom_token": null,
            "wecom_encoding_aes_key": null,
            "wecom_corp_id": null,
            "wecom_agent_id": null,
            "wecom_corp_secret": null,
            "wecom_kf_secret": null,
            "api_key": "test-api-key",
            // Keep the broker wait out of the test's critical path: with no
            // worker connected, forward_message would otherwise block.
            "message_timeout_secs": 0,
        }))
        .expect("test config should deserialize")
    }

    fn app(allow_plaintext: bool) -> Router {
        let cfg = config(allow_plaintext);
        let broker = Arc::new(MessageBroker::new(cfg.clone()));
        build_router(WebhookState {
            config: cfg,
            broker,
            crypto: None,
        })
    }

    /// signature = SHA1(sort(token, timestamp, nonce)) — the 3-value form.
    fn sign(timestamp: &str, nonce: &str) -> String {
        WechatCrypto::sign(TOKEN, timestamp, nonce)
    }

    fn now() -> String {
        chrono::Utc::now().timestamp().to_string()
    }

    async fn post(app: Router, query: &str, body: &str) -> StatusCode {
        app.oneshot(
            HttpRequest::builder()
                .method("POST")
                .uri(format!("/wechat/webhook?{query}"))
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap()
        .status()
    }

    const PLAIN_XML: &str = "<xml><ToUserName><![CDATA[gh_1]]></ToUserName>\
<FromUserName><![CDATA[victim]]></FromUserName><CreateTime>1</CreateTime>\
<MsgType><![CDATA[text]]></MsgType><Content><![CDATA[injected]]></Content>\
<MsgId>1</MsgId></xml>";

    #[tokio::test]
    async fn a_plaintext_post_is_refused_even_with_a_valid_signature() {
        // The 3-value signature does not cover the body, so accepting plaintext
        // means one captured triple can carry any message the attacker likes.
        let (ts, nonce) = (now(), "abc");
        let q = format!(
            "signature={}&timestamp={ts}&nonce={nonce}",
            sign(&ts, nonce)
        );
        assert_eq!(post(app(false), &q, PLAIN_XML).await, StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn a_plaintext_post_is_accepted_once_explicitly_allowed() {
        let (ts, nonce) = (now(), "abc");
        let q = format!(
            "signature={}&timestamp={ts}&nonce={nonce}",
            sign(&ts, nonce)
        );
        assert_eq!(post(app(true), &q, PLAIN_XML).await, StatusCode::OK);
    }

    #[tokio::test]
    async fn an_encrypted_post_without_msg_signature_is_refused() {
        // msg_signature is the only value that binds the request to its body.
        let (ts, nonce) = (now(), "abc");
        let q = format!(
            "signature={}&timestamp={ts}&nonce={nonce}&encrypt_type=aes",
            sign(&ts, nonce)
        );
        let body = "<xml><ToUserName><![CDATA[gh_1]]></ToUserName>\
<Encrypt><![CDATA[ZmFrZQ==]]></Encrypt></xml>";
        assert_eq!(
            post(app(false), &q, body).await,
            StatusCode::FORBIDDEN,
            "a parseable encrypted body with no msg_signature must be refused, \
             not passed through to decryption"
        );
    }

    #[tokio::test]
    async fn a_replayed_signature_expires() {
        // Same shape as the accepted case, but with a timestamp from long ago.
        let stale = (chrono::Utc::now().timestamp() - 3600).to_string();
        let nonce = "abc";
        let q = format!(
            "signature={}&timestamp={stale}&nonce={nonce}",
            sign(&stale, nonce)
        );
        assert_eq!(
            post(app(true), &q, PLAIN_XML).await,
            StatusCode::FORBIDDEN,
            "an hour-old signature must not still authorize a POST"
        );
    }

    #[tokio::test]
    async fn a_wrong_signature_is_refused() {
        let (ts, nonce) = (now(), "abc");
        let q = format!("signature=deadbeef&timestamp={ts}&nonce={nonce}");
        assert_eq!(post(app(true), &q, PLAIN_XML).await, StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn get_verification_echoes_the_challenge_and_rejects_a_stale_one() {
        let nonce = "abc";

        let ts = now();
        let q = format!(
            "signature={}&timestamp={ts}&nonce={nonce}&echostr=challenge",
            sign(&ts, nonce)
        );
        let res = app(false)
            .oneshot(
                HttpRequest::builder()
                    .uri(format!("/wechat/webhook?{q}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let body = axum::body::to_bytes(res.into_body(), 1024).await.unwrap();
        assert_eq!(&body[..], b"challenge");

        let stale = (chrono::Utc::now().timestamp() - 3600).to_string();
        let q = format!(
            "signature={}&timestamp={stale}&nonce={nonce}&echostr=challenge",
            sign(&stale, nonce)
        );
        let res = app(false)
            .oneshot(
                HttpRequest::builder()
                    .uri(format!("/wechat/webhook?{q}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::FORBIDDEN);
    }
}
