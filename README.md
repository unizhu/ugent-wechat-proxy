# UGENT WeChat Proxy

A public-facing proxy server that bridges WeChat Official Account and WeCom (Enterprise WeChat) webhooks to local UGENT instances via WebSocket.

## Architecture

```
┌─────────────────┐          ┌──────────────────────────────┐
│  WeChat OA      │          │  ugent-wechat-proxy          │
│  (公众号)       │  HTTPS   │  (Public VPS)                │
│  Webhook        │ ────────▶│  :8080                       │
└─────────────────┘          │                              │                             │
                             │  WeCom (企业微信) Webhook    │
┌─────────────────┐          │  :8082                       │
│  WeCom          │  HTTPS   │                              │
│  Webhook        │ ────────▶│  WebSocket server :8081      │
└─────────────────┘          │  • Message broker            │
                             │  • Async reply support       │
                             │  • Message storage           │
                             │  • Media cache               │
                             └──────────────┬───────────────┘
                                            │
                              WebSocket (bidirectional)
                                            │
                             ┌──────────────▼───────────────┐
                             │  UGENT (Local Network)       │
                             │  • Connects OUT to proxy     │
                             │  • Processes messages        │
                             │  • Sends responses back      │
                             └───────────────��──────────────┘
```

## Features

- ✅ WeChat OA webhook verification (SHA1 signature)
- ✅ AES-256-CBC message encryption/decryption
- ✅ **WeCom (企业微信) support** — separate webhook listener on port 8082
- ✅ WebSocket server for UGENT connections
- ✅ API key authentication
- ✅ Bidirectional messaging with broadcast
- ✅ **Async reply via Customer Service API** (48h window)
- ✅ **Template Message fallback** (for delayed notifications)
- ✅ **Message storage** — SQLite persistence with configurable retention
- ✅ **Media cache** — downloads and caches images/voice from WeChat/WeCom
- ✅ **WeCom KF (Customer Service) API** — separate secret for sync_msg

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

### 5. Configure WeCom (Optional)

Set your webhook URL in WeCom admin console:
```
https://your-domain.com/wecom/callback
```

### 6. Connect UGENT

UGENT connects via WebSocket to receive messages:

```json
// 1. Connect to wss://your-server:8081/ws
// 2. Authenticate
{"type": "auth", "data": {"client_id": "ugent-main", "api_key": "your_api_key"}}

// 3. Receive messages
{"type": "message", "data": {...}}

// 4. Send responses
{"type": "response", "original_id": "message-uuid", "content": "Reply text"}
```

## Configuration

All configuration is via environment variables (or `.env` file).

### WeChat Official Account (公众号)

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `WECHAT_TOKEN` | ✅ | — | WeChat token for signature verification |
| `PROXY_API_KEY` | ✅ | — | API key for UGENT WebSocket clients |
| `WECHAT_ENCODING_AES_KEY` | ❌ | — | 43-char AES key (security mode) |
| `WECHAT_APP_ID` | ❌ | — | WeChat AppID (for decryption & API calls) |
| `WECHAT_APP_SECRET` | ❌ | — | AppSecret (for async reply API) |
| `WECHAT_TEMPLATE_RESPONSE_READY` | ❌ | — | Template ID for delayed notifications |
| `WECHAT_WEBHOOK_PATH` | ❌ | `/wechat/webhook` | WeChat OA webhook route path |
| `WEBHOOK_ADDR` | ❌ | `0.0.0.0:8080` | Webhook bind address |

### WeCom (企业微信)

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `WECOM_ENABLED` | ❌ | disabled | Set to any value to enable WeCom support |
| `WECOM_TOKEN` | ❌ | — | Token for signature verification |
| `WECOM_ENCODING_AES_KEY` | ❌ | — | 43-char AES key |
| `WECOM_CORP_ID` | ❌ | — | Enterprise CorpID |
| `WECOM_AGENT_ID` | ❌ | — | Application AgentID (numeric) |
| `WECOM_CORP_SECRET` | ❌ | — | CorpSecret for general API calls |
| `WECOM_KF_SECRET` | ❌ | — | Separate secret for Customer Service API (sync_msg) |
| `WECOM_CALLBACK_PATH` | ❌ | `/wecom/callback` | WeCom webhook callback route path |
| `WECOM_WEBHOOK_ADDR` | ❌ | `0.0.0.0:8082` | WeCom webhook bind address |

### Server & Networking

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `WEBSOCKET_ADDR` | ❌ | `0.0.0.0:8081` | WebSocket server bind address |
| `ALLOWED_CLIENTS` | ❌ | (all) | Comma-separated allowed client IDs |
| `MAX_CONNECTIONS_PER_CLIENT` | ❌ | `10` | Max WS connections per client |

### Timing & Limits

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `MESSAGE_TIMEOUT_SECS` | ❌ | `5` | Response timeout (WeChat limit) |
| `RATE_LIMIT` | ❌ | `100` | Messages per minute per client |

### Storage

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `STORAGE_ENABLED` | ❌ | disabled | Set to any value to enable message storage |
| `STORAGE_PATH` | ❌ | `~/.ugent/database/wecom_cache.db` | SQLite database path |
| `MESSAGE_RETENTION_DAYS` | ❌ | `30` | Message retention days (0 = forever) |

### Media Cache

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `MEDIA_CACHE_DIR` | ❌ | `/tmp/ugent-media-cache` | Directory for downloaded media files |

### Debugging

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `DEBUG_MODE` | ❌ | disabled | Set to any value to enable debug logging |
| `RUST_LOG` | ❌ | `info,ugent_wechat_proxy=debug` | Rust log filter |

## Async Reply Flow

When UGENT doesn't respond within the timeout (5s), the proxy automatically:

1. **Customer Service API** — Sends "processing" message (works within 48h of user's last message)
2. **Template Message** — Fallback if rate limited (requires template configuration)

```
WeChat msg → Proxy → UGENT (5s timeout)
                    ↓ (timeout)
         Customer Service API reply
                    ↓ (if rate limited)
           Template Message notification
```

## Deployment

### Production `.env` Location

The systemd service expects the env file at:
```
/opt/ugent-wechat-proxy/.env
```

Copy the example and fill in real values:
```bash
mkdir -p /opt/ugent-wechat-proxy
cp .env.example /opt/ugent-wechat-proxy/.env
vim /opt/ugent-wechat-proxy/.env
```

### With Caddy (Recommended)

```Caddyfile
wechat.yourdomain.com {
    # WeChat OA webhook
    handle /wechat/* {
        reverse_proxy 127.0.0.1:8080
    }

    # WeCom webhook
    handle /wecom/* {
        reverse_proxy 127.0.0.1:8082
    }

    # WebSocket
    handle /ws {
        reverse_proxy 127.0.0.1:8081
    }
}
```

Caddy automatically provisions HTTPS via Let's Encrypt — no cert config needed.

### With Docker

```bash
# Build
docker build -t ugent-wechat-proxy .

# Run
docker run -d \
  --name wechat-proxy \
  -p 8080:8080 \
  -p 8081:8081 \
  -p 8082:8082 \
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
User=root
WorkingDirectory=/opt/ugent-wechat-proxy
EnvironmentFile=/opt/ugent-wechat-proxy/.env
ExecStart=/usr/bin/ugent-wechat-proxy
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

## Ports

| Port | Protocol | Purpose |
|------|----------|---------|
| 8080 | HTTP | WeChat OA webhook listener |
| 8081 | WebSocket | UGENT client connections |
| 8082 | HTTP | WeCom webhook listener |

## Troubleshooting

```bash
# Live logs (note: wechat, not wchat!)
journalctl -u ugent-wechat-proxy -f

# Recent errors only
journalctl -u ugent-wechat-proxy -p err --since "10 min ago"

# Check what's connecting to WebSocket port
ss -tnp | grep 8081

# Verify Caddy is proxying correctly
caddy validate --config /etc/caddy/Caddyfile
```

## Security Notes

- Always use HTTPS in production (Caddy + automatic Let's Encrypt)
- Keep `PROXY_API_KEY`, `WECHAT_APP_SECRET`, `WECOM_CORP_SECRET`, and `WECOM_KF_SECRET` secure
- Use `WECHAT_ENCODING_AES_KEY` / `WECOM_ENCODING_AES_KEY` for message encryption (security mode)
- Restrict `ALLOWED_CLIENTS` to known client IDs
- Set `RATE_LIMIT` to prevent abuse
- Enable `STORAGE_ENABLED` only if you need message history

## License

MIT
