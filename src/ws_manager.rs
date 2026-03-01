//! WebSocket manager for UGENT client connections

use axum::{
    Router,
    extract::{
        ConnectInfo, State,
        ws::{Message, WebSocket, WebSocketUpgrade},
    },
    response::Response,
    routing::get,
};
use dashmap::DashMap;
use futures_util::{SinkExt, StreamExt};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::{broadcast, mpsc};
use tracing::{debug, error, info, warn};

use crate::broker::MessageBroker;
use crate::types::{ProxyMessage, WsMessage};

/// WebSocket manager state
#[derive(Clone)]
pub struct WebSocketManager {
    pub broker: Arc<MessageBroker>,
    /// Connected clients: client_id -> (addr, tx)
    clients: Arc<DashMap<String, (SocketAddr, mpsc::Sender<WsMessage>)>>,
}

impl WebSocketManager {
    pub fn new(broker: Arc<MessageBroker>) -> Self {
        Self {
            broker,
            clients: Arc::new(DashMap::new()),
        }
    }

    /// Add a client connection
    pub fn add_client(&self, client_id: String, addr: SocketAddr, tx: mpsc::Sender<WsMessage>) {
        self.clients.insert(client_id.clone(), (addr, tx));
        self.broker.set_default_client(client_id.clone());

        // Detect channel-specific clients based on client_id
        let client_lower = client_id.to_lowercase();
        if client_lower.contains("wecom")
            || client_lower.contains("wechat-work")
            || client_lower.contains("wx-work")
        {
            self.broker.set_wecom_client(client_id.clone());
        } else if client_lower.contains("wechat") {
            self.broker.set_wechat_client(client_id.clone());
        }

        info!("Client {} connected from {}", client_id, addr);
    }

    /// Remove a client connection
    pub fn remove_client(&self, client_id: &str) {
        if self.clients.remove(client_id).is_some() {
            self.broker.clear_default_client(client_id);
            info!("Client {} disconnected", client_id);
        }
    }

    /// Get connected client count
    pub fn client_count(&self) -> usize {
        self.clients.len()
    }
}

/// Run the WebSocket server
pub async fn run_server(addr: SocketAddr, ws_manager: Arc<WebSocketManager>) -> anyhow::Result<()> {
    let app = Router::new()
        .route("/ws", get(websocket_handler))
        .with_state(ws_manager)
        .into_make_service_with_connect_info::<SocketAddr>();

    let listener = tokio::net::TcpListener::bind(addr).await?;
    info!("WebSocket server listening on {}", addr);
    axum::serve(listener, app).await?;

    Ok(())
}

/// WebSocket upgrade handler
async fn websocket_handler(
    ws: WebSocketUpgrade,
    State(ws_manager): State<Arc<WebSocketManager>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
) -> Response {
    ws.on_upgrade(move |socket| handle_socket(socket, ws_manager, addr))
}

/// Handle WebSocket connection
async fn handle_socket(socket: WebSocket, ws_manager: Arc<WebSocketManager>, addr: SocketAddr) {
    debug!("New WebSocket connection from {}", addr);

    let (mut ws_tx, mut ws_rx) = socket.split();

    // Channel for outgoing messages to this client
    let (tx, mut rx) = mpsc::channel::<WsMessage>(32);

    // State for this connection
    let mut authenticated = false;
    let mut client_id: Option<String> = None;

    // Task to send outgoing messages to WebSocket
    let send_task = tokio::spawn(async move {
        while let Some(msg) = rx.recv().await {
            let json = serde_json::to_string(&msg).unwrap();
            if ws_tx.send(Message::Text(json.into())).await.is_err() {
                break;
            }
        }
    });

    // Receive messages from client
    while let Some(msg) = ws_rx.next().await {
        match msg {
            Ok(Message::Text(text)) => {
                match serde_json::from_str::<WsMessage>(&text) {
                    Ok(ws_msg) => {
                        match ws_msg {
                            WsMessage::Auth { data } => {
                                // Validate API key
                                if data.api_key == ws_manager.broker.config.api_key {
                                    if !ws_manager.broker.config.is_client_allowed(&data.client_id)
                                    {
                                        let _ = tx
                                            .send(WsMessage::AuthResult {
                                                success: false,
                                                message: "Client not allowed".to_string(),
                                            })
                                            .await;
                                        continue;
                                    }

                                    // Check max connections
                                    let current_count = ws_manager.client_count();
                                    if current_count
                                        >= ws_manager.broker.config.max_connections_per_client
                                    {
                                        let _ = tx
                                            .send(WsMessage::AuthResult {
                                                success: false,
                                                message: "Max connections reached".to_string(),
                                            })
                                            .await;
                                        continue;
                                    }

                                    // Authentication successful
                                    authenticated = true;
                                    client_id = Some(data.client_id.clone());
                                    ws_manager.add_client(data.client_id.clone(), addr, tx.clone());

                                    // Subscribe to broker messages for this client
                                    let broker_rx = ws_manager.broker.subscribe();
                                    let tx_clone = tx.clone();
                                    let cid = data.client_id.clone();
                                    tokio::spawn(async move {
                                        handle_broker_messages(broker_rx, tx_clone, cid).await;
                                    });

                                    let _ = tx
                                        .send(WsMessage::AuthResult {
                                            success: true,
                                            message: "Authenticated successfully".to_string(),
                                        })
                                        .await;

                                    info!("Client {} authenticated", data.client_id);
                                } else {
                                    let _ = tx
                                        .send(WsMessage::AuthResult {
                                            success: false,
                                            message: "Invalid API key".to_string(),
                                        })
                                        .await;
                                    warn!("Authentication failed for client {}", data.client_id);
                                }
                            }
                            WsMessage::Response {
                                original_id,
                                content,
                            } => {
                                if !authenticated {
                                    warn!("Unauthenticated client tried to send response");
                                    continue;
                                }

                                // Forward response to broker
                                if let Some(ref cid) = client_id
                                    && let Err(e) = ws_manager
                                        .broker
                                        .handle_response(cid, original_id, content)
                                        .await
                                {
                                    error!("Error handling response: {}", e);
                                }
                            }
                            WsMessage::Ping => {
                                let _ = tx.send(WsMessage::Pong).await;
                            }
                            _ => {
                                if !authenticated {
                                    warn!("Unauthenticated client sent message");
                                }
                            }
                        }
                    }
                    Err(e) => {
                        warn!("Failed to parse WebSocket message: {}", e);
                    }
                }
            }
            Ok(Message::Pong(_)) => {
                debug!("Received pong");
            }
            Ok(Message::Close(_)) => {
                info!("Client closed connection");
                break;
            }
            Err(e) => {
                error!("WebSocket error: {}", e);
                break;
            }
            _ => {}
        }
    }

    // Cleanup
    if let Some(cid) = client_id {
        ws_manager.remove_client(&cid);
    }

    send_task.abort();
}

/// Handle incoming messages from broker and forward to WebSocket client
async fn handle_broker_messages(
    mut broker_rx: broadcast::Receiver<ProxyMessage>,
    tx: mpsc::Sender<WsMessage>,
    client_id: String,
) {
    loop {
        match broker_rx.recv().await {
            Ok(proxy_msg) => {
                // Only forward messages meant for this client
                if proxy_msg.client_id == client_id {
                    debug!(
                        "Forwarding message {} to client {}",
                        proxy_msg.id, client_id
                    );
                    if tx
                        .send(WsMessage::Message {
                            data: Box::new(proxy_msg),
                        })
                        .await
                        .is_err()
                    {
                        debug!("Client {} disconnected, stopping broker handler", client_id);
                        break;
                    }
                }
            }
            Err(broadcast::error::RecvError::Closed) => {
                debug!("Broker channel closed for client {}", client_id);
                break;
            }
            Err(broadcast::error::RecvError::Lagged(n)) => {
                warn!("Client {} lagged behind by {} messages", client_id, n);
                // Continue processing, lagged messages are dropped
            }
        }
    }
}
