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

        // Priority 2: Local file path.
        //
        // The worker is a separate process, usually on a separate host, so this
        // path is attacker-controlled input. Every path — relative included —
        // is canonicalized and then required to sit inside the temp directory.
        //
        // Canonicalizing first is what makes the check sound: it resolves `..`
        // and follows symlinks, so containment is decided on the real target
        // rather than on the spelling. The previous version only checked
        // absolute paths, which left a relative `.env` resolving against the
        // process CWD — the same directory the systemd unit keeps its
        // EnvironmentFile in.
        if let Some(ref path_str) = artifact.local_path {
            let path = Path::new(path_str);

            let canonical_path = path
                .canonicalize()
                .map_err(|e| anyhow!("Failed to resolve artifact path {:?}: {}", path, e))?;

            let temp_dir = std::env::temp_dir();
            let canonical_temp = temp_dir.canonicalize().unwrap_or(temp_dir);

            if !canonical_path.starts_with(&canonical_temp) {
                return Err(anyhow!(
                    "Refusing to read artifact outside the temp directory: {:?}",
                    path
                ));
            }

            return fs::read(&canonical_path)
                .await
                .with_context(|| format!("Failed to read artifact file: {:?}", canonical_path));
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

    fn handler() -> OutboundMediaHandler {
        OutboundMediaHandler::new(
            Arc::new(WecomApiClient::new(
                "ww123456".to_string(),
                "secret".to_string(),
                1,
            )),
            None,
        )
    }

    fn artifact_at(local_path: &str) -> OutboundArtifact {
        OutboundArtifact {
            kind: OutboundArtifactKind::Document,
            name: "x".to_string(),
            data: None,
            local_path: Some(local_path.to_string()),
            url: None,
            content_type: None,
            caption: None,
            size_bytes: None,
        }
    }

    #[tokio::test]
    async fn a_relative_path_cannot_escape_the_temp_directory() {
        // Regression: relative paths used to skip containment entirely and were
        // read from the process CWD — which the deployed systemd unit sets to
        // the directory holding the EnvironmentFile, so `.env` was readable by
        // any worker that could reach the WebSocket port.
        let err = handler()
            .get_artifact_data(&artifact_at(".env"))
            .await
            .expect_err("a relative path must not be read");
        let msg = err.to_string();
        assert!(
            msg.contains("Refusing to read artifact outside the temp directory")
                || msg.contains("Failed to resolve artifact path"),
            "unexpected error: {msg}"
        );
    }

    #[tokio::test]
    async fn an_absolute_path_outside_temp_is_refused() {
        // /etc/hosts is real and readable, so passing this proves the
        // containment check ran rather than the open merely failing.
        let err = handler()
            .get_artifact_data(&artifact_at("/etc/hosts"))
            .await
            .expect_err("/etc/hosts must not be readable as an artifact");
        assert!(
            err.to_string()
                .contains("Refusing to read artifact outside the temp directory"),
            "unexpected error: {err}"
        );
    }

    #[tokio::test]
    async fn a_file_inside_temp_is_still_readable() {
        let dir = std::env::temp_dir().join("ugent-outbound-containment-test");
        tokio::fs::create_dir_all(&dir).await.unwrap();
        let path = dir.join("ok.txt");
        tokio::fs::write(&path, b"payload").await.unwrap();

        let bytes = handler()
            .get_artifact_data(&artifact_at(path.to_str().unwrap()))
            .await
            .expect("a file inside the temp directory should still be sendable");
        assert_eq!(bytes, b"payload");

        tokio::fs::remove_dir_all(&dir).await.ok();
    }

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

    // The three tests below previously compared constants to literals, which is
    // always true and exercised none of the code. They now call validate_size.

    #[test]
    fn test_validate_size_ok() {
        let h = handler();
        for kind in [
            OutboundArtifactKind::Image,
            OutboundArtifactKind::Audio,
            OutboundArtifactKind::Video,
            OutboundArtifactKind::Document,
        ] {
            assert!(h.validate_size(&kind, 1000).is_ok(), "{kind:?}");
        }
    }

    #[test]
    fn test_validate_size_too_small() {
        assert!(
            handler()
                .validate_size(&OutboundArtifactKind::Image, MIN_FILE_SIZE - 1)
                .is_err()
        );
    }

    #[test]
    fn test_validate_size_exceeded() {
        let h = handler();
        // WeCom enforces a different ceiling per type, so each is checked
        // against its own limit rather than a shared one.
        for (kind, max) in [
            (OutboundArtifactKind::Image, MAX_IMAGE_SIZE),
            (OutboundArtifactKind::Audio, MAX_VOICE_SIZE),
            (OutboundArtifactKind::Video, MAX_VIDEO_SIZE),
            (OutboundArtifactKind::Document, MAX_FILE_SIZE),
        ] {
            assert!(h.validate_size(&kind, max).is_ok(), "{kind:?} at limit");
            assert!(
                h.validate_size(&kind, max + 1).is_err(),
                "{kind:?} one byte over the limit must be refused"
            );
        }
    }
}
