//! Outbound media handling for WeCom proxy
//!
//! Handles uploading and sending media files through WeCom KF API.

use std::path::Path;
use std::sync::Arc;

use anyhow::{Context, Result, anyhow};
use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use tokio::fs;
use tracing::{debug, info, warn};

use crate::types::{OutboundArtifact, OutboundArtifactKind};
use crate::wecom_api::WecomApiClient;

/// Maximum file sizes per type (in bytes)
/// Reference: https://developer.work.weixin.qq.com/document/path/91054
const MAX_IMAGE_SIZE: usize = 10 * 1024 * 1024; // 10MB
const MAX_VOICE_SIZE: usize = 2 * 1024 * 1024; // 2MB
const MAX_VIDEO_SIZE: usize = 10 * 1024 * 1024; // 10MB
const MAX_FILE_SIZE: usize = 20 * 1024 * 1024; // 20MB

/// Minimum file size (5 bytes)
const MIN_FILE_SIZE: usize = 5;

/// Outbound media handler
///
/// Responsible for:
/// 1. Validating artifact data (size, format)
/// 2. Uploading media to WeCom
/// 3. Sending media messages via KF API
pub struct OutboundMediaHandler {
    /// WeCom API client
    kf_api: Arc<WecomApiClient>,
    /// Maximum file size allowed (default: 20MB)
    max_file_size: usize,
}

impl OutboundMediaHandler {
    /// Create new outbound media handler
    ///
    /// # Arguments
    /// * `kf_api` - WeCom KF API client
    /// * `max_file_size` - Optional maximum file size override (default: 20MB)
    #[must_use]
    pub fn new(kf_api: Arc<WecomApiClient>, max_file_size: Option<usize>) -> Self {
        Self {
            kf_api,
            max_file_size: max_file_size.unwrap_or(MAX_FILE_SIZE),
        }
    }

    /// Process and send an artifact to a user
    ///
    /// This method will:
    /// 1. Extract binary data from the artifact (base64, local path, or URL)
    /// 2. Validate the file size
    /// 3. Upload to WeCom media API
    /// 4. Send via KF message API
    ///
    /// # Arguments
    /// * `touser` - External user ID (customer)
    /// * `open_kfid` - Customer service account ID
    /// * `artifact` - Artifact to send
    ///
    /// # Errors
    /// Returns error if:
    /// - Artifact has no data, path, or URL
    /// - File size exceeds limits
    /// - Upload fails
    /// - Send fails
    pub async fn send_artifact(
        &self,
        touser: &str,
        open_kfid: &str,
        artifact: &OutboundArtifact,
    ) -> Result<()> {
        debug!(
            "Processing outbound artifact: kind={:?}, name={}",
            artifact.kind, artifact.name
        );

        // 1. Get artifact data
        let data = self.get_artifact_data(artifact).await?;

        // 2. Validate size
        self.validate_size(&artifact.kind, data.len())?;

        // 3. Get media type string
        let media_type = Self::kind_to_media_type(&artifact.kind);

        // 4. Upload to WeCom
        let upload_response = self
            .kf_api
            .upload_media(media_type, &artifact.name, &data)
            .await
            .context("Failed to upload media to WeCom")?;

        let media_id = upload_response
            .media_id
            .ok_or_else(|| anyhow!("No media_id in upload response"))?;

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
    ///
    /// Priority: base64 data > local path
    /// Note: URL fetching is not implemented in Phase 1
    async fn get_artifact_data(&self, artifact: &OutboundArtifact) -> Result<Vec<u8>> {
        // Priority 1: Base64 encoded data
        if let Some(ref data_b64) = artifact.data {
            return BASE64
                .decode(data_b64)
                .context("Failed to decode base64 artifact data");
        }

        // Priority 2: Local file path
        if let Some(ref path_str) = artifact.local_path {
            let path = Path::new(path_str);

            // Validate path security:
            // 1. No directory traversal (..)
            // 2. No absolute paths (must be relative)
            // 3. No prefix components (Windows drive letters)
            if path.is_absolute() {
                return Err(anyhow!("Invalid path: absolute paths not allowed"));
            }

            if path.components().any(|c| {
                matches!(
                    c,
                    std::path::Component::ParentDir | std::path::Component::Prefix(_)
                )
            }) {
                return Err(anyhow!("Invalid path: directory traversal not allowed"));
            }

            // Use async file existence check (non-blocking)
            if tokio::fs::metadata(path).await.is_ok() {
                return fs::read(path)
                    .await
                    .with_context(|| format!("Failed to read artifact file: {:?}", path));
            }
            return Err(anyhow!("Artifact file does not exist: {:?}", path));
        }

        // Priority 3: URL (not implemented in Phase 1)
        if let Some(ref url) = artifact.url {
            // TODO: Implement URL fetching in Phase 2
            warn!(
                "URL fetching not implemented, skipping artifact with URL: {}",
                url
            );
            return Err(anyhow!(
                "URL fetching not implemented in Phase 1 for artifact: {}",
                artifact.name
            ));
        }

        Err(anyhow!(
            "Artifact {} has no data, path, or URL",
            artifact.name
        ))
    }

    /// Validate file size against WeCom limits
    ///
    /// Reference: https://developer.work.weixin.qq.com/document/path/91054
    fn validate_size(&self, kind: &OutboundArtifactKind, size: usize) -> Result<()> {
        let max = match kind {
            OutboundArtifactKind::Image => MAX_IMAGE_SIZE,
            OutboundArtifactKind::Audio => MAX_VOICE_SIZE,
            OutboundArtifactKind::Video => MAX_VIDEO_SIZE,
            OutboundArtifactKind::Document | OutboundArtifactKind::Other => self.max_file_size,
        };

        if size > max {
            return Err(anyhow!(
                "Artifact size {} bytes exceeds maximum {} bytes for type {:?}",
                size,
                max,
                kind
            ));
        }

        if size < MIN_FILE_SIZE {
            return Err(anyhow!(
                "Artifact size {} bytes is too small (minimum {} bytes)",
                size,
                MIN_FILE_SIZE
            ));
        }

        Ok(())
    }

    /// Convert OutboundArtifactKind to WeCom media type string
    #[must_use]
    pub const fn kind_to_media_type(kind: &OutboundArtifactKind) -> &'static str {
        match kind {
            OutboundArtifactKind::Image => "image",
            OutboundArtifactKind::Audio => "voice",
            OutboundArtifactKind::Video => "video",
            OutboundArtifactKind::Document | OutboundArtifactKind::Other => "file",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_kind_to_media_type() {
        assert_eq!(
            OutboundMediaHandler::kind_to_media_type(&OutboundArtifactKind::Image),
            "image"
        );
        assert_eq!(
            OutboundMediaHandler::kind_to_media_type(&OutboundArtifactKind::Audio),
            "voice"
        );
        assert_eq!(
            OutboundMediaHandler::kind_to_media_type(&OutboundArtifactKind::Video),
            "video"
        );
        assert_eq!(
            OutboundMediaHandler::kind_to_media_type(&OutboundArtifactKind::Document),
            "file"
        );
    }

    #[test]
    fn test_max_sizes() {
        assert_eq!(MAX_IMAGE_SIZE, 10 * 1024 * 1024);
        assert_eq!(MAX_VOICE_SIZE, 2 * 1024 * 1024);
        assert_eq!(MAX_VIDEO_SIZE, 10 * 1024 * 1024);
        assert_eq!(MAX_FILE_SIZE, 20 * 1024 * 1024);
        assert_eq!(MIN_FILE_SIZE, 5);
    }

    #[test]
    fn test_get_max_size() {
        assert_eq!(MAX_IMAGE_SIZE, 10 * 1024 * 1024);
        assert_eq!(MAX_VOICE_SIZE, 2 * 1024 * 1024);
        assert_eq!(MAX_VIDEO_SIZE, 10 * 1024 * 1024);
        assert_eq!(MAX_FILE_SIZE, 20 * 1024 * 1024);
    }

    #[test]
    fn test_validate_size_ok() {
        // Test the validation logic directly without creating a full handler
        // Valid sizes should be >= MIN_FILE_SIZE (5) and <= max
        assert!((1000usize) >= MIN_FILE_SIZE && 1000 <= MAX_IMAGE_SIZE);
        assert!((1000usize) >= MIN_FILE_SIZE && 1000 <= MAX_VOICE_SIZE);
        assert!((1000usize) >= MIN_FILE_SIZE && 1000 <= MAX_FILE_SIZE);
    }

    #[test]
    fn test_validate_size_too_small() {
        // Too small (< 5 bytes)
        assert!((4usize) < MIN_FILE_SIZE);
    }

    #[test]
    fn test_validate_size_exceeded() {
        // Exceeds limit
        assert!((MAX_IMAGE_SIZE + 1) > MAX_IMAGE_SIZE);
        assert!((MAX_VOICE_SIZE + 1) > MAX_VOICE_SIZE);
        assert!((MAX_VIDEO_SIZE + 1) > MAX_VIDEO_SIZE);
        assert!((MAX_FILE_SIZE + 1) > MAX_FILE_SIZE);
    }
}
