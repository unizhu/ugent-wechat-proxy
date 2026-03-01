//! Media cache management for WeCom multimedia files
//!
//! Provides utilities for caching downloaded media files from WeCom,
//! including images and voice recordings.

use std::path::PathBuf;

use anyhow::{Context, Result};
use tokio::fs;
use tracing::debug;

/// Maximum file size for media files (20MB - WeCom limit for files)
pub const MAX_FILE_SIZE: usize = 20 * 1024 * 1024;

/// Media cache manager
#[derive(Debug, Clone)]
pub struct MediaCache {
    /// Cache directory path
    cache_dir: PathBuf,
}

impl MediaCache {
    /// Create a new media cache
    pub fn new(cache_dir: impl Into<PathBuf>) -> Self {
        Self {
            cache_dir: cache_dir.into(),
        }
    }

    /// Generate a file path for a media ID
    fn get_path(&self, media_id: &str, media_type: &str) -> PathBuf {
        let extension = match media_type {
            "image" => "jpg", // WeCom images are typically JPG
            "voice" => "amr", // WeCom voice is AMR format
            "video" => "mp4", // WeCom video is MP4
            "file" => "bin",  // Generic file
            _ => "bin",
        };
        self.cache_dir.join(format!("{}.{}", media_id, extension))
    }

    /// Save media data to cache
    pub async fn save(&self, media_id: &str, media_type: &str, data: &[u8]) -> Result<PathBuf> {
        // Validate size
        if data.len() > MAX_FILE_SIZE {
            return Err(anyhow::anyhow!(
                "Media file too large: {} bytes (max: {})",
                data.len(),
                MAX_FILE_SIZE
            ));
        }

        let path = self.get_path(media_id, media_type);

        // Ensure directory exists
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .await
                .with_context(|| format!("Failed to create parent directory: {:?}", parent))?;
        }

        // Write file
        fs::write(&path, data)
            .await
            .with_context(|| format!("Failed to write media file: {:?}", path))?;

        debug!(
            "Saved media {} to {:?} ({} bytes)",
            media_id,
            path,
            data.len()
        );
        Ok(path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_path() {
        let cache = MediaCache::new("/tmp/test-cache");

        let path = cache.get_path("media123", "image");
        assert_eq!(path, PathBuf::from("/tmp/test-cache/media123.jpg"));

        let path = cache.get_path("voice456", "voice");
        assert_eq!(path, PathBuf::from("/tmp/test-cache/voice456.amr"));
    }

    #[test]
    fn test_max_file_size() {
        assert_eq!(MAX_FILE_SIZE, 20 * 1024 * 1024);
    }
}
