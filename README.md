# UGENT WeChat Proxy

A public-facing proxy server that bridges WeChat Official Account webhooks to local UGENT instances via WebSocket.

## Architecture

```
┌─────────────┐         ┌──────────────────────────┐
│   WeChat    │  HTTPS  │  ugent-wechat-proxy      │
│   Server    │ ───────▶│  (Public VPS)            │
└─────────────┘         │                          │
                        │  • HTTPS webhook (8080)  │
                        │  • WebSocket (8081)      │
                        │  • Message broker        │
                        └────────────┬─────────────┘
                                     │
                        WebSocket (bidirectional)
                                     │
                        ┌────────────▼─────────────┐
                        │  UGENT (Local Network)   │
                        │  • Connects OUT to proxy │
                        │  • Processes messages    │
                        │  • Sends responses back  │
                        └──────────────────────────┘
```

## Features

- ✅ WeChat webhook verification (SHA1 signature)
- ✅ AES-256-CBC message encryption/decryption
- ✅ WebSocket server for UGENT connections
- ✅ API key authentication
- ✅ Rate limiting
- ✅ Bidirectional messaging

## Quick Start

### 1. Install

```bash
cargo install --path .
```

### 2. Configure Environment

```bash
# Required
export WECHAT_TOKEN=your_wechat_token
export PROXY_API_KEY=your_secure_api_key

# Optional (for encrypted messages)
export WECHAT_ENCODING_AES_KEY=your_43_char_key
export WECHAT_APP_ID=wx1234567890abcdef

# Server configuration
export WEBHOOK_ADDR=0.0.0.0:8080
export WEBSOCKET_ADDR=0.0.0.0:8081
```

### 3. Run

```bash
ugent-wechat-proxy
```

### 4. Configure WeChat Official Account

Set your webhook URL in WeChat MP platform:
```
https://your-domain.com/wechat/webhook
```

### 5. Connect UGENT

UGENT connects via WebSocket to receive messages:

```json
// 1. Connect to ws://your-server:8081/ws
// 2. Authenticate
{"type": "auth", "data": {"client_id": "ugent-main", "api_key": "your_api_key"}}

// 3. Receive messages
{"type": "message", "data": {...}}

// 4. Send responses
{"type": "response", "original_id": "message-uuid", "content": "Reply text"}
```

## Configuration

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `WECHAT_TOKEN` | ✅ | - | WeChat token for signature |
| `PROXY_API_KEY` | ✅ | - | API key for UGENT clients |
| `WECHAT_ENCODING_AES_KEY` | ❌ | - | 43-char AES key (security mode) |
| `WECHAT_APP_ID` | ❌ | - | WeChat AppID (for decryption) |
| `WEBHOOK_ADDR` | ❌ | `0.0.0.0:8080` | Webhook bind address |
| `WEBSOCKET_ADDR` | ❌ | `0.0.0.0:8081` | WebSocket bind address |
| `ALLOWED_CLIENTS` | ❌ | (all) | Comma-separated client IDs |
| `MESSAGE_TIMEOUT_SECS` | ❌ | `5` | Response timeout |
| `MAX_CONNECTIONS_PER_CLIENT` | ❌ | `10` | Max WS connections |
| `RATE_LIMIT` | ❌ | `100` | Messages per minute |
| `DEBUG_MODE` | ❌ | `false` | Enable debug logging |

## Deployment

### With nginx (Recommended)

```nginx
server {
    listen 443 ssl http2;
    server_name wechat.yourdomain.com;

    ssl_certificate /etc/letsencrypt/live/wechat.yourdomain.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/wechat.yourdomain.com/privkey.pem;

    # WeChat webhook
    location /wechat {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }

    # WebSocket
    location /ws {
        proxy_pass http://127.0.0.1:8081;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
    }
}
```

### With Docker

```dockerfile
FROM rust:1.75 as builder
WORKDIR /app
COPY . .
RUN cargo build --release

FROM debian:bookworm-slim
COPY --from=builder /app/target/release/ugent-wechat-proxy /usr/local/bin/
CMD ["ugent-wechat-proxy"]
```

```bash
docker build -t ugent-wechat-proxy .
docker run -p 8080:8080 -p 8081:8081 \
  -e WECHAT_TOKEN=xxx \
  -e PROXY_API_KEY=xxx \
  ugent-wechat-proxy
```

## Protocol

### WebSocket Message Types

#### Authentication
```json
// Request
{"type": "auth", "data": {"client_id": "ugent-1", "api_key": "secret"}}

// Response
{"type": "auth_result", "success": true, "message": "Authenticated"}
```

#### Incoming Message
```json
{
  "type": "message",
  "data": {
    "id": "uuid",
    "timestamp": "2026-01-01T00:00:00Z",
    "direction": "inbound",
    "client_id": "ugent-1",
    "wechat_message": {
      "to_user_name": "gh_xxx",
      "from_user_name": "openid_xxx",
      "create_time": 1234567890,
      "msg_type": "text",
      "content": "Hello"
    },
    "raw_xml": "<xml>...</xml>"
  }
}
```

#### Response
```json
{"type": "response", "original_id": "uuid", "content": "Reply text"}
```

#### Heartbeat
```json
// Request
{"type": "ping"}

// Response
{"type": "pong"}
```

## Security

1. **WeChat Verification**: SHA1 signature validation
2. **Message Encryption**: AES-256-CBC (security mode)
3. **API Key Auth**: All WebSocket clients must authenticate
4. **Client Allowlist**: Optional restriction of client IDs
5. **Rate Limiting**: Configurable per-client rate limits

## License

MIT
