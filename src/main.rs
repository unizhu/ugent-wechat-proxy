//! UGENT WeChat Proxy - Main Entry Point
//!
//! A public-facing proxy server that:
//! 1. Receives webhooks from WeChat Official Account platform
//! 2. Forwards messages to connected UGENT instances via WebSocket
//! 3. Returns responses from UGENT back to WeChat
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

use anyhow::Result;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::signal;
use tracing::info;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

mod broker;
mod config;
mod crypto;
mod media_cache;
mod outbound;
mod storage;
mod types;
mod webhook;
mod wechat_api;
mod wecom_api;
mod wecom_webhook;
mod ws_manager;

use broker::MessageBroker;
use config::ProxyConfig;
use storage::MessageStore;
use ws_manager::WebSocketManager;

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::new(
            std::env::var("RUST_LOG").unwrap_or_else(|_| "info,ugent_wechat_proxy=debug".into()),
        ))
        .with(tracing_subscriber::fmt::layer())
        .init();

    info!("🚀 UGENT WeChat Proxy starting...");

    // Load configuration
    let config = ProxyConfig::from_env()?;
    info!("📋 Configuration loaded");

    // Initialize storage if enabled
    let storage = if config.storage_enabled {
        match MessageStore::new(&config.storage_path) {
            Ok(store) => {
                info!("📦 Storage initialized at {:?}", config.storage_path);
                Some(Arc::new(store))
            }
            Err(e) => {
                tracing::error!("Failed to initialize storage: {}", e);
                None
            }
        }
    } else {
        info!("📦 Storage disabled");
        None
    };

    // Create shared state
    let broker = Arc::new(MessageBroker::new(config.clone()));
    let ws_manager = Arc::new(WebSocketManager::new(broker.clone()));

    // Spawn webhook server
    let webhook_addr: SocketAddr = config.webhook_addr.parse()?;
    let webhook_server = spawn_webhook_server(webhook_addr, broker.clone());

    // Spawn WeCom webhook server if enabled
    let wecom_server = if config.wecom_enabled {
        let wecom_addr: SocketAddr = config.wecom_webhook_addr.parse()?;
        Some(spawn_wecom_server(
            wecom_addr,
            broker.clone(),
            storage.clone(),
        ))
    } else {
        info!("⏭️ WeCom webhook server disabled");
        None
    };

    // Spawn WebSocket server
    let ws_addr: SocketAddr = config.websocket_addr.parse()?;
    let ws_server = spawn_websocket_server(ws_addr, ws_manager.clone());

    info!(
        "🌐 WeChat webhook server listening on {}",
        config.webhook_addr
    );
    if config.wecom_enabled {
        info!(
            "🏢 WeCom webhook server listening on {}",
            config.wecom_webhook_addr
        );
    }
    info!("🔌 WebSocket server listening on {}", config.websocket_addr);

    // Wait for shutdown signal
    match signal::ctrl_c().await {
        Ok(()) => info!("📢 Shutdown signal received"),
        Err(err) => tracing::error!("Unable to listen for shutdown signal: {}", err),
    }

    // Graceful shutdown
    info!("🛑 Shutting down servers...");
    webhook_server.abort();
    if let Some(server) = wecom_server {
        server.abort();
    }
    ws_server.abort();

    info!("✅ UGENT WeChat Proxy stopped");
    Ok(())
}

/// Spawn the webhook HTTP server
fn spawn_webhook_server(
    addr: SocketAddr,
    broker: Arc<MessageBroker>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        if let Err(e) = webhook::run_server(addr, broker).await {
            tracing::error!("Webhook server error: {}", e);
        }
    })
}

/// Spawn the WebSocket server
fn spawn_websocket_server(
    addr: SocketAddr,
    ws_manager: Arc<WebSocketManager>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        if let Err(e) = ws_manager::run_server(addr, ws_manager).await {
            tracing::error!("WebSocket server error: {}", e);
        }
    })
}

/// Spawn the WeCom webhook HTTP server
fn spawn_wecom_server(
    addr: SocketAddr,
    broker: Arc<MessageBroker>,
    storage: Option<Arc<MessageStore>>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        if let Err(e) = wecom_webhook::run_server(addr, broker, storage).await {
            tracing::error!("WeCom webhook server error: {}", e);
        }
    })
}
