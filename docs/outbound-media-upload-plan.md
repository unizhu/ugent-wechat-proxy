# Outbound Media Upload Support Plan for ugent-wechat-proxy

**Author:** UGENT  
**Date:** 2025-01-13  
**Status:** ✅ COMPLETED

---

## 1. Executive Summary

The current `ugent-wechat-proxy` supports **inbound media download** (images, voice) but **does NOT support outbound media upload** through the WebSocket protocol. This document outlines a comprehensive plan to add full media upload support for the proxy mode.

### Current State

| Feature | Status |
|---------|--------|
| Inbound Text Messages | ✅ Supported |
| Inbound Image Download | ✅ Supported |
| Inbound Voice Download | ✅ Supported |
| Outbound Text Messages | ✅ Supported |
| Outbound Image Upload | ❌ **NOT Supported** |
| Outbound Voice Upload | ❌ **NOT Supported** |
| Outbound Video Upload | ❌ **NOT Supported** |
| Outbound File Upload | ❌ **NOT Supported** |

### Target State

All outbound media types (image, voice, video, file) will be supported through the proxy WebSocket.

---

## 2. WeCom Media API Reference

### 2.1 Upload Temporary Media API

**Endpoint:** `POST https://qyapi.weixin.qq.com/cgi-bin/media/upload?access_token=ACCESS_TOKEN&type={TYPE}`

**Supported Types:**
- `image` - 10MB max, JPG/PNG
- `voice` - 2MB max, AMR format only, max 60s
- `video` - 10MB max, MP4 format
- `file` - 20MB max

**Request Format:** `multipart/form-data`

```http
POST /cgi-bin/media/upload?access_token=ACCESS_TOKEN&type=image HTTP/1.1
Content-Type: multipart/form-data; boundary=----BOUNDARY

------BOUNDARY
Content-Disposition: form-data; name="media"; filename="image.jpg"; filelength=1024
Content-Type: image/jpg

[binary data]
------BOUNDARY--
```

**Response:**
```json
{
    "errcode": 0,
    "errmsg": "ok",
    "type": "image",
    "media_id": "MEDIA_ID",
    "created_at": 1234567890
}
```

### 2.2 Send KF Media Message API

**Endpoint:** `POST https://qyapi.weixin.qq.com/cgi-bin/kf/send_msg?access_token=ACCESS_TOKEN`

**Image Message:**
```json
{
    "touser": "EXTERNAL_USERID",
    "open_kfid": "OPEN_KFID",
    "msgtype": "image",
    "image": {
        "media_id": "MEDIA_ID"
    }
}
```

**Voice Message:**
```json
{
    "touser": "EXTERNAL_USERID",
    "open_kfid": "OPEN_KFID",
    "msgtype": "voice",
    "voice": {
        "media_id": "MEDIA_ID"
    }
}
```

**Video Message:**
```json
{
    "touser": "EXTERNAL_USERID",
    "open_kfid": "OPEN_KFID",
    "msgtype": "video",
    "video": {
        "media_id": "MEDIA_ID"
    }
}
```

**File Message:**
```json
{
    "touser": "EXTERNAL_USERID",
    "open_kfid": "OPEN_KFID",
    "msgtype": "file",
    "file": {
        "media_id": "MEDIA_ID"
    }
}
```

---

## 3. Architecture Design

### 3.1 Current Architecture (Text-Only)

```
┌─────────────┐         ┌──────────────────┐         ┌─────────────────┐
│   UGENT     │  WS     │  ugent-wechat    │   HTTP  │   WeCom API     │
│   Plugin    │ ◄─────► │     proxy        │ ◄─────► │                 │
│             │         │                  │         │                 │
│ Response:   │         │  WsMessage::     │         │  kf/send_msg    │
│ {text only} │         │  Response {      │         │  (text only)    │
│             │         │    content: str  │         │                 │
│             │         │  }               │         │                 │
└─────────────┘         └──────────────────┘         └─────────────────┘
```

### 3.2 Proposed Architecture (With Media Support)

```
┌─────────────────┐         ┌──────────────────┐         ┌─────────────────┐
│    UGENT        │  WS     │  ugent-wechat    │   HTTP  │   WeCom API     │
│    Plugin       │ ◄─────► │     proxy        │ ◄─────► │                 │
│                 │         │                  │         │                 │
│ Response:       │         │  WsMessage::     │         │  1. media/upload│
│ {               │         │  Response {      │         │     ↓ media_id  │
│   content,      │         │    content,      │         │  2. kf/send_msg │
│   artifacts: [  │         │    artifacts     │         │     (media)     │
│     {           │         │  }               │         │                 │
│       kind,     │         │                  │         │                 │
│       data,     │         │  OutboundMedia:: │         │                 │
│       filename  │         │  upload_media()  │         │                 │
│     }           │         │         ↓        │         │                 │
│   ]             │         │      media_id    │         │                 │
│ }               │         │         ↓        │         │                 │
│                 │         │  send_kf_media() │         │                 │
└─────────────────┘         └──────────────────┘         └─────────────────┘
```

### 3.3 Data Flow

```
1. UGENT Plugin generates response with artifacts
   ↓
2. Plugin sends WsMessage::Response { content, artifacts } via WebSocket
   ↓
3. Proxy receives message, detects artifacts
   ↓
4. For each artifact:
   a. Extract binary data (base64 decoded or read from local path)
   b. Call POST /media/upload → get media_id
   c. Store media_id
   ↓
5. Send text message (if content not empty)
   ↓
6. For each media_id:
   Call POST /kf/send_msg with media_id
   ↓
7. Return success to plugin
```

---

## 4. Protocol Design

### 4.1 New Types

#### 4.1.1 `OutboundArtifact` (types.rs)

```rust
/// Artifact to send to user (file, image, voice, video)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum OutboundArtifactKind {
    Image,
    Voice,
    Video,
    File,
}

/// Outbound artifact from UGENT to send via WeCom
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutboundArtifact {
    /// Type of artifact
    pub kind: OutboundArtifactKind,
    
    /// File name (for display purposes)
    pub name: String,
    
    /// Base64 encoded data (preferred for small files)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<String>,
    
    /// Local file path (alternative to data, for large files)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    
    /// Remote URL (optional, may be used as fallback)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    
    /// MIME type hint
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mime_type: Option<String>,
    
    /// Caption for the artifact
    #[serde(skip_serializing_if = "Option::is_none")]
    pub caption: Option<String>,
}
```

#### 4.1.2 Updated `WsMessage` (types.rs)

```rust
/// WebSocket message types
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum WsMessage {
    /// Authentication request
    Auth { data: ClientAuth },
    
    /// Authentication response
    AuthResult { success: bool, message: String },
    
    /// Incoming message from WeChat or WeCom
    Message { data: Box<ProxyMessage> },
    
    /// Response to a message (updated with artifacts support)
    Response {
        original_id: Uuid,
        content: String,
        /// Artifacts to send (images, files, etc.)
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        artifacts: Vec<OutboundArtifact>,
    },
    
    /// Heartbeat
    Ping,
    
    /// Heartbeat response
    Pong,
}
```

#### 4.1.3 `UploadMediaResponse` (wecom_api.rs)

```rust
/// Response from /media/upload API
#[derive(Debug, Clone, Deserialize)]
pub struct UploadMediaResponse {
    pub errcode: i32,
    pub errmsg: String,
    #[serde(default)]
    pub type_: Option<String>,
    #[serde(default)]
    pub media_id: Option<String>,
    #[serde(default)]
    pub created_at: Option<i64>,
}
```

---

## 5. Implementation Plan

### 5.1 Phase 1: Core Types and Protocol (types.rs)

**Files to modify:** `src/types.rs`

**Tasks:**
1. Add `OutboundArtifactKind` enum
2. Add `OutboundArtifact` struct
3. Update `WsMessage::Response` to include `artifacts` field
4. Add serialization tests

**Estimated lines:** ~50 lines

---

### 5.2 Phase 2: Media Upload API Client (wecom_api.rs)

**Files to modify:** `src/wecom_api.rs`

**Tasks:**

#### 5.2.1 Add `upload_media` method

```rust
impl WecomApiClient {
    /// Upload media file to WeCom
    ///
    /// API: POST /media/upload?access_token=ACCESS_TOKEN&type={type}
    /// Docs: https://developer.work.weixin.qq.com/document/path/91054
    pub async fn upload_media(
        &self,
        media_type: &str,  // "image", "voice", "video", "file"
        filename: &str,
        data: &[u8],
    ) -> Result<UploadMediaResponse> {
        let access_token = self.get_access_token().await?;
        
        let url = format!(
            "{}/media/upload?access_token={}&type={}",
            WECOM_API_BASE, access_token, media_type
        );
        
        // Build multipart form
        let part = Part::bytes(data.to_vec())
            .file_name(filename.to_string())
            .mime_str(Self::get_mime_type(media_type))?;
        
        let form = Form::new().part("media", part);
        
        let response = self.http
            .post(&url)
            .multipart(form)
            .send()
            .await?
            .json::<UploadMediaResponse>()
            .await?;
        
        if response.errcode != 0 {
            return Err(anyhow!(
                "Media upload error {}: {}",
                response.errcode, response.errmsg
            ));
        }
        
        info!(
            "Uploaded media {} successfully, media_id={:?}",
            filename, response.media_id
        );
        
        Ok(response)
    }
    
    fn get_mime_type(media_type: &str) -> &'static str {
        match media_type {
            "image" => "image/jpeg",
            "voice" => "audio/amr",
            "video" => "video/mp4",
            "file" => "application/octet-stream",
            _ => "application/octet-stream",
        }
    }
}
```

#### 5.2.2 Add `send_kf_media_message` method

```rust
impl WecomApiClient {
    /// Send KF media message (image, voice, video, file)
    ///
    /// API: POST /kf/send_msg?access_token=ACCESS_TOKEN
    /// Docs: https://developer.work.weixin.qq.com/document/path/94677
    pub async fn send_kf_media_message(
        &self,
        touser: &str,
        open_kfid: &str,
        media_type: &str,  // "image", "voice", "video", "file"
        media_id: &str,
    ) -> Result<WecomApiResponse> {
        let access_token = self.get_access_token().await?;
        
        let url = format!(
            "{}/kf/send_msg?access_token={}",
            WECOM_API_BASE, access_token
        );
        
        let body = serde_json::json!({
            "touser": touser,
            "open_kfid": open_kfid,
            "msgtype": media_type,
            media_type: {
                "media_id": media_id
            }
        });
        
        debug!(
            "Sending KF {} message to user={}, open_kfid={}",
            media_type, touser, open_kfid
        );
        
        let response = self.http
            .post(&url)
            .json(&body)
            .send()
            .await?
            .json::<WecomApiResponse>()
            .await?;
        
        if response.errcode != 0 {
            return Err(anyhow!(
                "KF send_msg API error {}: {}",
                response.errcode, response.errmsg
            ));
        }
        
        info!(
            "Sent KF {} message to {} successfully",
            media_type, touser
        );
        
        Ok(response)
    }
}
```

**Estimated lines:** ~100 lines

---

### 5.3 Phase 3: Outbound Media Handler (new file: outbound.rs)

**New file:** `src/outbound.rs`

```rust
//! Outbound media handling for WeCom proxy
//!
//! Handles uploading and sending media files through WeCom KF API.

use std::path::Path;
use std::sync::Arc;

use anyhow::{Context, Result};
use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use tokio::fs;
use tracing::{debug, error, info, warn};

use crate::types::{OutboundArtifact, OutboundArtifactKind};
use crate::wecom_api::WecomApiClient;

/// Maximum file sizes per type (in bytes)
const MAX_IMAGE_SIZE: usize = 10 * 1024 * 1024;  // 10MB
const MAX_VOICE_SIZE: usize = 2 * 1024 * 1024;   // 2MB
const MAX_VIDEO_SIZE: usize = 10 * 1024 * 1024;  // 10MB
const MAX_FILE_SIZE: usize = 20 * 1024 * 1024;   // 20MB

/// Outbound media handler
pub struct OutboundMediaHandler {
    /// WeCom API client
    kf_api: Arc<WecomApiClient>,
    /// Maximum file size allowed (default: 20MB)
    max_file_size: usize,
}

impl OutboundMediaHandler {
    /// Create new outbound media handler
    pub fn new(kf_api: Arc<WecomApiClient>, max_file_size: Option<usize>) -> Self {
        Self {
            kf_api,
            max_file_size: max_file_size.unwrap_or(MAX_FILE_SIZE),
        }
    }
    
    /// Process and send an artifact
    pub async fn send_artifact(
        &self,
        touser: &str,
        open_kfid: &str,
        artifact: &OutboundArtifact,
    ) -> Result<()> {
        // 1. Get artifact data
        let data = self.get_artifact_data(artifact).await?;
        
        // 2. Validate size
        self.validate_size(&artifact.kind, data.len())?;
        
        // 3. Get media type string
        let media_type = Self::kind_to_media_type(&artifact.kind);
        
        // 4. Upload to WeCom
        let upload_response = self.kf_api
            .upload_media(media_type, &artifact.name, &data)
            .await
            .context("Failed to upload media to WeCom")?;
        
        let media_id = upload_response.media_id
            .ok_or_else(|| anyhow::anyhow!("No media_id in upload response"))?;
        
        info!(
            "Uploaded artifact {} as media_id={}",
            artifact.name, media_id
        );
        
        // 5. Send via KF API
        self.kf_api
            .send_kf_media_message(touser, open_kfid, media_type, &media_id)
            .await
            .context("Failed to send media message via KF API")?;
        
        info!(
            "Sent {} artifact '{}' to {}",
            media_type, artifact.name, touser
        );
        
        Ok(())
    }
    
    /// Get binary data from artifact
    async fn get_artifact_data(&self, artifact: &OutboundArtifact) -> Result<Vec<u8>> {
        // Priority: base64 data > local path > URL
        if let Some(ref data_b64) = artifact.data {
            return BASE64
                .decode(data_b64)
                .context("Failed to decode base64 artifact data");
        }
        
        if let Some(ref path) = artifact.path {
            let path = Path::new(path);
            if path.exists() {
                return fs::read(path)
                    .await
                    .with_context(|| format!("Failed to read artifact file: {:?}", path));
            }
        }
        
        // TODO: Support URL fetch for remote artifacts
        // if let Some(ref url) = artifact.url {
        //     return self.fetch_url(url).await;
        // }
        
        Err(anyhow::anyhow!(
            "Artifact {} has no data, path, or URL",
            artifact.name
        ))
    }
    
    /// Validate file size against limits
    fn validate_size(&self, kind: &OutboundArtifactKind, size: usize) -> Result<()> {
        let max = match kind {
            OutboundArtifactKind::Image => MAX_IMAGE_SIZE,
            OutboundArtifactKind::Voice => MAX_VOICE_SIZE,
            OutboundArtifactKind::Video => MAX_VIDEO_SIZE,
            OutboundArtifactKind::File => self.max_file_size,
        };
        
        if size > max {
            return Err(anyhow::anyhow!(
                "Artifact size {} exceeds maximum {} bytes for type {:?}",
                size, max, kind
            ));
        }
        
        if size < 5 {
            return Err(anyhow::anyhow!(
                "Artifact size {} is too small (minimum 5 bytes)",
                size
            ));
        }
        
        Ok(())
    }
    
    /// Convert OutboundArtifactKind to WeCom media type string
    fn kind_to_media_type(kind: &OutboundArtifactKind) -> &'static str {
        match kind {
            OutboundArtifactKind::Image => "image",
            OutboundArtifactKind::Voice => "voice",
            OutboundArtifactKind::Video => "video",
            OutboundArtifactKind::File => "file",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_kind_to_media_type() {
        assert_eq!(OutboundMediaHandler::kind_to_media_type(&OutboundArtifactKind::Image), "image");
        assert_eq!(OutboundMediaHandler::kind_to_media_type(&OutboundArtifactKind::Voice), "voice");
        assert_eq!(OutboundMediaHandler::kind_to_media_type(&OutboundArtifactKind::Video), "video");
        assert_eq!(OutboundMediaHandler::kind_to_media_type(&OutboundArtifactKind::File), "file");
    }
    
    #[test]
    fn test_max_sizes() {
        assert_eq!(MAX_IMAGE_SIZE, 10 * 1024 * 1024);
        assert_eq!(MAX_VOICE_SIZE, 2 * 1024 * 1024);
        assert_eq!(MAX_VIDEO_SIZE, 10 * 1024 * 1024);
        assert_eq!(MAX_FILE_SIZE, 20 * 1024 * 1024);
    }
}
```

**Estimated lines:** ~200 lines

---

### 5.4 Phase 4: Update Broker (broker.rs)

**Files to modify:** `src/broker.rs`

**Changes:**

#### 5.4.1 Add outbound media handler field

```rust
pub struct MessageBroker {
    // ... existing fields ...
    
    /// Outbound media handler (for sending files, images, etc.)
    outbound_media: Option<Arc<OutboundMediaHandler>>,
}
```

#### 5.4.2 Update `handle_response` method

```rust
pub async fn handle_response(
    &self,
    _client_id: &str,
    original_id: Uuid,
    content: String,
    artifacts: Vec<OutboundArtifact>,
) -> Result<()> {
    debug!(
        "Received response for message {} from client with {} artifacts",
        original_id, artifacts.len()
    );
    
    if let Some((_, pending)) = self.pending.remove(&original_id) {
        // Check if this is a KF (Customer Service) message
        if let (Some(kf_open_kfid), Some(kf_api)) = (&pending.kf_open_kfid, &self.kf_api) {
            let user_id = &pending.original_from_user;
            
            // 1. Send text message (if content not empty)
            if !content.trim().is_empty() {
                match kf_api
                    .send_kf_text_message(user_id, kf_open_kfid, &content)
                    .await
                {
                    Ok(resp) if resp.errcode == 0 => {
                        info!("KF text reply sent to {}", user_id);
                    }
                    Ok(resp) => {
                        warn!("Failed to send KF text reply: {} - {}", resp.errcode, resp.errmsg);
                    }
                    Err(e) => {
                        error!("Error sending KF text reply: {}", e);
                    }
                }
            }
            
            // 2. Send artifacts (images, files, etc.)
            if !artifacts.is_empty() {
                if let Some(ref handler) = self.outbound_media {
                    for artifact in &artifacts {
                        if let Err(e) = handler.send_artifact(user_id, kf_open_kfid, artifact).await {
                            error!("Failed to send artifact {}: {}", artifact.name, e);
                        }
                    }
                } else {
                    warn!("Outbound media handler not available, skipping {} artifacts", artifacts.len());
                }
            }
            
            return Ok(());
        }
        
        // Non-KF message handling (existing XML response logic)
        // ... existing code ...
    }
    
    Ok(())
}
```

**Estimated lines:** ~50 lines modified

---

### 5.5 Phase 5: Update WebSocket Manager (ws_manager.rs)

**Files to modify:** `src/ws_manager.rs`

**Changes:**

Update the message handler to pass artifacts to broker:

```rust
WsMessage::Response { original_id, content, artifacts } => {
    if !authenticated {
        warn!("Unauthenticated client tried to send response");
        continue;
    }
    
    if let Some(ref cid) = client_id {
        if let Err(e) = ws_manager
            .broker
            .handle_response(cid, original_id, content, artifacts)
            .await
        {
            error!("Error handling response: {}", e);
        }
    }
}
```

**Estimated lines:** ~10 lines modified

---

### 5.6 Phase 6: Configuration (config.rs)

**Files to modify:** `src/config.rs`

**Add new config options:**

```rust
/// Outbound media configuration
#[derive(Debug, Clone, Deserialize)]
pub struct OutboundMediaConfig {
    /// Enable outbound image sending
    #[serde(default = "default_true")]
    pub enable_outbound_image: bool,
    
    /// Enable outbound voice sending
    #[serde(default = "default_true")]
    pub enable_outbound_voice: bool,
    
    /// Enable outbound video sending
    #[serde(default = "default_true")]
    pub enable_outbound_video: bool,
    
    /// Enable outbound file sending
    #[serde(default = "default_true")]
    pub enable_outbound_file: bool,
    
    /// Maximum file size for uploads (bytes)
    #[serde(default = "default_max_upload_size")]
    pub max_upload_size: usize,
    
    /// Temporary directory for file processing
    #[serde(default = "default_upload_temp_dir")]
    pub upload_temp_dir: String,
}

fn default_max_upload_size() -> usize {
    20 * 1024 * 1024  // 20MB
}

fn default_upload_temp_dir() -> String {
    "/tmp/ugent-proxy-uploads".to_string()
}

impl ProxyConfig {
    pub fn from_env() -> Result<Self> {
        // ... existing code ...
        
        let outbound_media = OutboundMediaConfig {
            enable_outbound_image: parse_env_bool("PROXY_ENABLE_OUTBOUND_IMAGE", true),
            enable_outbound_voice: parse_env_bool("PROXY_ENABLE_OUTBOUND_VOICE", true),
            enable_outbound_video: parse_env_bool("PROXY_ENABLE_OUTBOUND_VIDEO", true),
            enable_outbound_file: parse_env_bool("PROXY_ENABLE_OUTBOUND_FILE", true),
            max_upload_size: std::env::var("PROXY_MAX_UPLOAD_SIZE")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or_else(default_max_upload_size),
            upload_temp_dir: std::env::var("PROXY_UPLOAD_TEMP_DIR")
                .unwrap_or_else(|_| default_upload_temp_dir()),
        };
        
        // ... rest of config ...
    }
}
```

**Estimated lines:** ~60 lines

---

### 5.7 Phase 7: Update lib.rs and main.rs

**Files to modify:** `src/lib.rs`, `src/main.rs`

Add new module exports:

```rust
// lib.rs
pub mod outbound;

pub use outbound::OutboundMediaHandler;
```

**Estimated lines:** ~5 lines

---

### 5.8 Phase 8: UGENT Plugin Update (channel-wecom plugin)

**Files to modify:** 
- `ugent-plugin/plugins/channel-wecom/src/outbound/mod.rs`
- `ugent-plugin/plugins/channel-wecom/src/outbound/upload.rs`

**Changes:**

1. Detect proxy mode from config
2. If proxy mode:
   - Encode artifacts as base64
   - Send via WebSocket with `WsMessage::Response { content, artifacts }`
3. If standalone mode:
   - Use existing direct upload logic

**Estimated lines:** ~100 lines

---

## 6. File Size Limits Summary

| Type | Max Size | Format | Notes |
|------|----------|--------|-------|
| Image | 10MB | JPG, PNG | Recommended: 2MB for faster upload |
| Voice | 2MB | AMR only | Max duration: 60 seconds |
| Video | 10MB | MP4 | Recommended: 5MB for faster processing |
| File | 20MB | Any | Generic file attachment |

---

## 7. Error Handling

### 7.1 Upload Errors

| Error Code | Description | Handling |
|------------|-------------|----------|
| 40001 | Invalid access_token | Retry with new token |
| 40009 | Media ID expired | Re-upload media |
| 45001 | File size exceeded | Reject with clear message |
| 45002 | Invalid media type | Reject with format requirements |

### 7.2 Fallback Strategy

1. **Upload fails**: Log error, continue with text-only response
2. **Send fails**: Queue for retry, notify via error callback
3. **File too large**: Return error to plugin, suggest compression

---

## 8. Testing Plan

### 8.1 Unit Tests

- [ ] `OutboundArtifact` serialization/deserialization
- [ ] `WsMessage::Response` with artifacts
- [ ] `upload_media` API client (mock HTTP)
- [ ] `send_kf_media_message` API client (mock HTTP)
- [ ] Size validation logic
- [ ] Base64 decode/encode

### 8.2 Integration Tests

- [ ] End-to-end: Plugin → Proxy → WeCom (mock)
- [ ] Image upload and send
- [ ] Voice upload and send
- [ ] Video upload and send
- [ ] File upload and send
- [ ] Mixed text + artifacts
- [ ] Error handling (oversized file)

### 8.3 Manual Testing

- [ ] Send image via WeCom to UGENT
- [ ] UGENT generates image response
- [ ] Verify image received on WeCom
- [ ] Test with various file sizes
- [ ] Test with various formats

---

## 9. Security Considerations

### 9.1 Input Validation

- Validate file size before processing
- Validate file type matches declared type
- Sanitize file names (no path traversal)
- Limit concurrent uploads per client

### 9.2 Resource Management

- Clean up temp files after processing
- Limit memory usage for base64 decode
- Implement upload timeouts
- Rate limiting per user

---

## 10. Migration Guide

### 10.1 For Plugin Developers

No breaking changes for text-only responses. To send media:

```json
{
    "type": "response",
    "original_id": "uuid-here",
    "content": "Here's the file you requested:",
    "artifacts": [
        {
            "kind": "file",
            "name": "document.pdf",
            "data": "base64-encoded-content-here"
        }
    ]
}
```

### 10.2 For Proxy Operators

Add to `.env` or environment:

```bash
# Outbound media settings (all default to true)
PROXY_ENABLE_OUTBOUND_IMAGE=true
PROXY_ENABLE_OUTBOUND_VOICE=true
PROXY_ENABLE_OUTBOUND_VIDEO=true
PROXY_ENABLE_OUTBOUND_FILE=true
PROXY_MAX_UPLOAD_SIZE=20971520
PROXY_UPLOAD_TEMP_DIR=/tmp/ugent-proxy-uploads
```

---

## 11. Timeline Estimate

| Phase | Description | Est. Time |
|-------|-------------|-----------|
| 1 | Core types and protocol | 2 hours |
| 2 | Media upload API client | 3 hours |
| 3 | Outbound media handler | 4 hours |
| 4 | Update broker | 2 hours |
| 5 | Update WebSocket manager | 1 hour |
| 6 | Configuration | 1 hour |
| 7 | Module exports | 0.5 hours |
| 8 | Plugin update | 3 hours |
| 9 | Testing | 4 hours |
| 10 | Documentation | 1 hour |
| **Total** | | **21.5 hours** |

---

## 12. Dependencies

### 12.1 Existing Dependencies

- `reqwest` - HTTP client (already used)
- `tokio` - Async runtime (already used)
- `serde` - JSON serialization (already used)
- `base64` - Base64 encoding (already used)
- `tracing` - Logging (already used)

### 12.2 No New Dependencies Required

All functionality can be implemented with existing dependencies.

---

## 13. Open Questions

1. **URL Fetching**: Should we support fetching artifacts from URLs?
   - Pros: Convenient for remote resources
   - Cons: Security risk, additional complexity
   - **Recommendation**: Phase 2 feature

2. **Async Uploads**: Should uploads happen in parallel?
   - Pros: Faster for multiple artifacts
   - Cons: Rate limiting complexity
   - **Recommendation**: Sequential for now, parallel in Phase 2

3. **Progress Reporting**: Should we report upload progress?
   - Pros: Better UX for large files
   - Cons: Requires WebSocket protocol change
   - **Recommendation**: Out of scope for Phase 1

---

## 14. Success Criteria

- [ ] Can send image files through proxy
- [ ] Can send voice files through proxy
- [ ] Can send video files through proxy
- [ ] Can send generic files through proxy
- [ ] File size limits are enforced
- [ ] Error handling is robust
- [ ] All tests pass
- [ ] No compiler warnings
- [ ] Documentation is complete

---

## 15. References

- [WeCom KF Send Message API](https://developer.work.weixin.qq.com/document/path/94677)
- [WeCom Media Upload API](https://developer.work.weixin.qq.com/document/path/91054)
- [WeCom Media Upload Overview](https://developer.work.weixin.qq.com/document/path/91054)

---

**End of Document**
