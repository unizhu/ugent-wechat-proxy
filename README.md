# UGENT WeChat Proxy

A public-facing proxy server that bridges WeChat Official Account webhooks to local UGENT instances via WebSocket.

## Architecture

```
┌─────────────┐         ┌──────────────────────────┐
│   WeChat    │  HTTPS  │  ugent-wechat-proxy      │
│   Server    │ ───────▶│  (Public VPS)            │
└─────────────┘         │                          │
                        │  • Webhook server (8080) │
                        │  • WebSocket server(8081)│
                        │  • Message broker        │
                        │  • Async reply support   │
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
- ✅ Bidirectional messaging with broadcast
- ✅ **Async reply via Customer Service API** (48h window)
- ✅ **Template Message fallback** (for delayed notifications)

## Quick Start

### 1. Install

```bash
cargo install --path .
```

### 2. Configure Environment

```bash
# Copy example config
cp .env.example .env
# Edit with your values
vim .env
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
| `WECHAT_TOKEN` | ✅ | - | WeChat token for signature verification |
| `PROXY_API_KEY` | ✅ | - | API key for UGENT WebSocket clients |
| `WECHAT_ENCODING_AES_KEY` | ❌ | - | 43-char AES key (security mode) |
| `WECHAT_APP_ID` | ❌ | - | WeChat AppID (for decryption) |
| `WECHAT_APP_SECRET` | ❌ | - | AppSecret (for async reply API) |
| `WECHAT_TEMPLATE_RESPONSE_READY` | ❌ | - | Template ID for delayed notifications |
| `WEBHOOK_ADDR` | ❌ | `0.0.0.0:8080` | Webhook bind address |
| `WEBSOCKET_ADDR` | ❌ | `0.0.0.0:8081` | WebSocket bind address |
| `ALLOWED_CLIENTS` | ❌ | (all) | Comma-separated client IDs |
| `MESSAGE_TIMEOUT_SECS` | ❌ | `5` | Response timeout (WeChat limit) |
| `MAX_CONNECTIONS_PER_CLIENT` | ❌ | `10` | Max WS connections per client |
| `RATE_LIMIT` | ❌ | `100` | Messages per minute per client |
| `DEBUG_MODE` | ❌ | `false` | Enable debug logging |

## Async Reply Flow

When UGENT doesn't respond within the timeout (5s), the proxy automatically:

1. **Customer Service API** - Sends "processing" message (works within 48h of user's last message)
2. **Template Message** - Fallback if rate limited (requires template configuration)

```
WeChat msg → Proxy → UGENT (5s timeout)
                    ↓ (timeout)
         Customer Service API reply
                    ↓ (if rate limited)
           Template Message notification
```

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

```bash
# Build
docker build -t ugent-wechat-proxy .

# Run
docker run -d \
  --name wechat-proxy \
  -p 8080:8080 \
  -p 8081:8081 \
  --env-file .env \
  ugent-wechat-proxy
```

### Systemd Service

```ini
[Unit]
Description=UGENT WeChat Proxy
After=network.target

[Service]
Type=simple
User=ugent
WorkingDirectory=/opt/ugent-wechat-proxy
EnvironmentFile=/opt/ugent-wechat-proxy/.env
ExecStart=/usr/local/bin/ugent-wechat-proxy
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

## Security Notes

- Always use HTTPS in production (nginx + Let's Encrypt)
- Keep `PROXY_API_KEY` and `WECHAT_APP_SECRET` secure
- Use `WECHAT_ENCODING_AES_KEY` for message encryption (security mode)
- Restrict `ALLOWED_CLIENTS` to known client IDs

## License

MIT
