//! UGENT WeChat Proxy Library
//!
//! A public-facing proxy server that bridges WeChat webhooks to local UGENT instances.
//!
//! # Architecture
//!
//! ```text
//! WeChat Server ──HTTPS──▶ Proxy (this) ──WebSocket──▶ UGENT (local)
//!                            │
//!                            ├── Webhook Server (port 8080)
//!                            ├── WebSocket Server (port 8081)
//!                            └── Message Broker (in-memory)
//! ```
//!
//! # Usage
//!
//! ## Running the proxy
//!
//! ```bash
//! # Set environment variables
//! export WECHAT_TOKEN=your_token
//! export PROXY_API_KEY=your_api_key
//! export WECHAT_ENCODING_AES_KEY=your_43_char_key  # optional
//! export WECHAT_APP_ID=wx1234567890abcdef          # optional
//!
//! # Run
//! ugent-wechat-proxy
//! ```
//!
//! ## Connecting from UGENT
//!
//! UGENT connects via WebSocket to the proxy:
//!
//! ```json
//! // 1. Authenticate
//! {"type": "auth", "data": {"client_id": "ugent-1", "api_key": "your_api_key"}}
//!
//! // 2. Receive messages
//! {"type": "message", "data": {...}}
//!
//! // 3. Send responses
//! {"type": "response", "original_id": "uuid", "content": "Reply text"}
//! ```

pub mod broker;
pub mod config;
pub mod crypto;
pub mod types;
pub mod webhook;
pub mod wechat_api;
pub mod ws_manager;

pub use broker::MessageBroker;
pub use config::ProxyConfig;
pub use crypto::WechatCrypto;
pub use types::*;
pub use wechat_api::WechatApiClient;
pub use ws_manager::WebSocketManager;

/// Prelude for common imports
pub mod prelude {
    pub use crate::broker::MessageBroker;
    pub use crate::config::ProxyConfig;
    pub use crate::crypto::WechatCrypto;
    pub use crate::types::*;
    pub use crate::ws_manager::WebSocketManager;
}
