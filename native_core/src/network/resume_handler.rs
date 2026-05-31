// ============================================
// SHADOW CATCHER - Resume Handler
// Handles interrupted download resumption
// ============================================

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use tokio::sync::RwLock;
use tracing::{info, debug, warn};
use serde::{Deserialize, Serialize};

use crate::utils::error::{ShadowError, ShadowResult};

// ─────────────────────────────────────────
// RESUME STATE
// ─────────────────────────────────────────

/// Saved state for a resumable download
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResumeState {
    /// Original download URL
    pub url: String,
    /// Output file path
    pub output_path: String,
    /// Bytes downloaded so far
    pub bytes_downloaded: u64,
    /// Total file size (0 if unknown)
    pub total_size: u64,
    /// ETag from server (for validation)
    pub etag: Option<String>,
    /// Last-Modified from server
    pub last_modified: Option<String>,
    /// Timestamp when state was saved (Unix seconds)
    pub saved_at: u64,
    /// Number of resume attempts
    pub resume_count: u32,
    /// Checksum of downloaded bytes so far
    pub partial_checksum: Option<String>,
}

impl ResumeState {
    /// Create a new resume state
    pub fn new(
        url: String,
        output_path: String,
        bytes_downloaded: u64,
        total_size: u64,
    ) -> Self {
        Self {
            url,
            output_path,
            bytes_downloaded,
            total_size,
            etag: None,
            last_modified: None,
            saved_at: Self::unix_timestamp(),
            resume_count: 0,
            partial_checksum: None,
        }
    }

    /// Progress percentage [0.0, 100.0]
    pub fn progress_pct(&self) -> f32 {
        if self.total_size == 0 {
            return 0.0;
        }
        self.bytes_downloaded as f32 / self.total_size as f32 * 100.0
    }

    /// Check if state is recent (within last 7 days)
    pub fn is_recent(&self) -> bool {
        let now = Self::unix_timestamp();
        let age_secs = now.saturating_sub(self.saved_at);
        age_secs < 7 * 24 * 3600
    }

    /// Get current Unix timestamp
    fn unix_timestamp() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }

    /// Check if this state is for the given URL
    pub fn matches_url(&self, url: &str) -> bool {
        self.url == url
    }
}

// ─────────────────────────────────────────
// RESUME HANDLER
// ─────────────────────────────────────────

/// Manages download resume state persistence
pub struct ResumeHandler {
    /// In-memory cache of resume states
    states: RwLock<HashMap<String, ResumeState>>,
    /// Directory to store resume state files
    state_dir: PathBuf,
}

impl ResumeHandler {
    /// Create a new resume handler
    pub fn new() -> Self {
        let state_dir = Self::default_state_dir();
        std::fs::create_dir_all(&state_dir).ok();

        let handler = Self {
            states: RwLock::new(HashMap::new()),
            state_dir,
        };

        // Load existing states from disk
        // (in background to not block construction)
        handler
    }

    /// Create with custom state directory
    pub fn with_state_dir(state_dir: PathBuf) -> Self {
        std::fs::create_dir_all(&state_dir).ok();
        Self {
            states: RwLock::new(HashMap::new()),
            state_dir,
        }
    }

    // ─────────────────────────────────────
    // PUBLIC API
    // ─────────────────────────────────────

    /// Get resume offset for a file path
    ///
    /// Returns 0 if no resume state found or
    /// if the partial file doesn't exist.
    pub async fn get_resume_offset(
        &self,
        output_path: &str,
    ) -> ShadowResult<u64> {
        // Check in-memory cache
        {
            let states = self.states.read().await;
            if let Some(state) = states.get(output_path) {
                if state.is_recent() {
                    // Verify partial file exists and has correct size
                    if let Ok(meta) = std::fs::metadata(output_path) {
                        let file_size = meta.len();
                        if file_size == state.bytes_downloaded {
                            debug!(
                                "Resume found: {} at {} bytes ({:.1}%)",
                                output_path,
                                state.bytes_downloaded,
                                state.progress_pct(),
                            );
                            return Ok(state.bytes_downloaded);
                        } else {
                            warn!(
                                "Resume mismatch: state={}, file={}",
                                state.bytes_downloaded, file_size
                            );
                        }
                    }
                }
            }
        }

        // Try loading from disk
        if let Ok(state) = self.load_state_from_disk(output_path) {
            if state.is_recent() {
                if let Ok(meta) = std::fs::metadata(output_path) {
                    let file_size = meta.len();
                    if file_size == state.bytes_downloaded
                        && file_size > 0
                    {
                        // Save to cache
                        self.states.write().await
                            .insert(output_path.to_string(), state.clone());

                        info!(
                            "Loaded resume state: {} at {} bytes",
                            output_path, state.bytes_downloaded
                        );
                        return Ok(state.bytes_downloaded);
                    }
                }
            }
        }

        Ok(0) // No valid resume state
    }

    /// Save download progress
    pub async fn save_progress(
        &self,
        output_path: &str,
        bytes_downloaded: u64,
    ) {
        let mut states = self.states.write().await;

        let state = states
            .entry(output_path.to_string())
            .or_insert_with(|| ResumeState::new(
                String::new(),
                output_path.to_string(),
                0,
                0,
            ));

        state.bytes_downloaded = bytes_downloaded;
        state.saved_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        drop(states);

        // Persist to disk (fire and forget)
        self.save_state_to_disk(output_path, bytes_downloaded).await;

        debug!(
            "Saved resume: {} at {} bytes",
            output_path, bytes_downloaded
        );
    }

    /// Save full resume state with URL info
    pub async fn save_state(
        &self,
        state: ResumeState,
    ) {
        let output_path = state.output_path.clone();
        let bytes = state.bytes_downloaded;

        self.states.write().await
            .insert(output_path.clone(), state);

        self.save_state_to_disk(&output_path, bytes).await;
    }

    /// Clear resume state for a completed download
    pub async fn clear(&self, output_path: &str) {
        self.states.write().await.remove(output_path);
        self.delete_state_file(output_path);
        debug!("Cleared resume state: {}", output_path);
    }

    /// Clear all resume states
    pub async fn clear_all(&self) {
        let paths: Vec<String> = self.states.read().await
            .keys()
            .cloned()
            .collect();

        for path in paths {
            self.delete_state_file(&path);
        }

        self.states.write().await.clear();
        info!("Cleared all resume states");
    }

    /// Get all active resume states
    pub async fn get_all_states(&self) -> Vec<ResumeState> {
        self.states.read().await
            .values()
            .cloned()
            .collect()
    }

    /// Get resume state for a specific file
    pub async fn get_state(
        &self,
        output_path: &str,
    ) -> Option<ResumeState> {
        self.states.read().await
            .get(output_path)
            .cloned()
    }

    /// Check if a download can be resumed
    pub async fn can_resume(&self, output_path: &str) -> bool {
        self.get_resume_offset(output_path).await
            .unwrap_or(0) > 0
    }

    /// Get count of resumable downloads
    pub async fn resumable_count(&self) -> usize {
        self.states.read().await.len()
    }

    /// Validate resume state against server
    pub async fn validate_state(
        &self,
        output_path: &str,
        server_etag: Option<&str>,
        server_last_modified: Option<&str>,
    ) -> bool {
        let states = self.states.read().await;
        if let Some(state) = states.get(output_path) {
            // If server provides ETag, validate it
            if let (Some(state_etag), Some(srv_etag)) =
                (&state.etag, server_etag)
            {
                if state_etag != srv_etag {
                    warn!(
                        "ETag mismatch - cannot resume: {}",
                        output_path
                    );
                    return false;
                }
            }
            return true;
        }
        false
    }

    // ─────────────────────────────────────
    // DISK PERSISTENCE
    // ─────────────────────────────────────

    /// Get state file path for an output path
    fn state_file_path(&self, output_path: &str) -> PathBuf {
        let filename = format!(
            "{}.resume",
            output_path
                .replace('/', "_")
                .replace('\\', "_")
                .replace(':', "_")
        );
        self.state_dir.join(filename)
    }

    /// Save state to disk
    async fn save_state_to_disk(
        &self,
        output_path: &str,
        bytes_downloaded: u64,
    ) {
        let state_path = self.state_file_path(output_path);
        let content = format!(
            "bytes={}\npath={}\ntimestamp={}",
            bytes_downloaded,
            output_path,
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        );

        tokio::fs::write(&state_path, content).await.ok();
    }

    /// Load state from disk
    fn load_state_from_disk(
        &self,
        output_path: &str,
    ) -> ShadowResult<ResumeState> {
        let state_path = self.state_file_path(output_path);

        let content = std::fs::read_to_string(&state_path)
            .map_err(|e| ShadowError::Io(e.to_string()))?;

        let mut bytes = 0u64;
        let mut saved_at = 0u64;

        for line in content.lines() {
            if let Some(val) = line.strip_prefix("bytes=") {
                bytes = val.parse().unwrap_or(0);
            }
            if let Some(val) = line.strip_prefix("timestamp=") {
                saved_at = val.parse().unwrap_or(0);
            }
        }

        Ok(ResumeState {
            url: String::new(),
            output_path: output_path.to_string(),
            bytes_downloaded: bytes,
            total_size: 0,
            etag: None,
            last_modified: None,
            saved_at,
            resume_count: 0,
            partial_checksum: None,
        })
    }

    /// Delete state file from disk
    fn delete_state_file(&self, output_path: &str) {
        let state_path = self.state_file_path(output_path);
        std::fs::remove_file(&state_path).ok();
    }

    /// Get default state directory
    fn default_state_dir() -> PathBuf {
        dirs::cache_dir()
            .unwrap_or_else(|| PathBuf::from("/tmp"))
            .join("shadow_catcher")
            .join("resume")
    }
}

impl Default for ResumeHandler {
    fn default() -> Self {
        Self::new()
    }
}

// ─────────────────────────────────────────
// TESTS
// ─────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn handler(dir: &TempDir) -> ResumeHandler {
        ResumeHandler::with_state_dir(dir.path().to_path_buf())
    }

    #[tokio::test]
    async fn test_no_resume_for_new_file() {
        let dir = tempfile::tempdir().unwrap();
        let h = handler(&dir);
        let offset = h.get_resume_offset("/tmp/new_file.mp4").await.unwrap();
        assert_eq!(offset, 0);
    }

    #[tokio::test]
    async fn test_save_and_load_progress() {
        let dir = tempfile::tempdir().unwrap();
        let h = handler(&dir);

        let output_path = dir.path()
            .join("test.mp4")
            .to_string_lossy()
            .to_string();

        // Create partial file
        std::fs::write(&output_path, b"a".repeat(500)).unwrap();

        h.save_progress(&output_path, 500).await;

        let offset = h.get_resume_offset(&output_path).await.unwrap();
        assert_eq!(offset, 500);
    }

    #[tokio::test]
    async fn test_clear_removes_state() {
        let dir = tempfile::tempdir().unwrap();
        let h = handler(&dir);

        let output_path = dir.path()
            .join("test2.mp4")
            .to_string_lossy()
            .to_string();

        std::fs::write(&output_path, b"b".repeat(1000)).unwrap();
        h.save_progress(&output_path, 1000).await;
        h.clear(&output_path).await;

        let offset = h.get_resume_offset(&output_path).await.unwrap();
        assert_eq!(offset, 0);
    }

    #[tokio::test]
    async fn test_resumable_count() {
        let dir = tempfile::tempdir().unwrap();
        let h = handler(&dir);

        h.save_progress("/tmp/file1.mp4", 100).await;
        h.save_progress("/tmp/file2.mp4", 200).await;

        assert_eq!(h.resumable_count().await, 2);
    }

    #[tokio::test]
    async fn test_clear_all() {
        let dir = tempfile::tempdir().unwrap();
        let h = handler(&dir);

        h.save_progress("/tmp/f1.mp4", 100).await;
        h.save_progress("/tmp/f2.mp4", 200).await;

        h.clear_all().await;
        assert_eq!(h.resumable_count().await, 0);
    }

    #[test]
    fn test_resume_state_progress_pct() {
        let state = ResumeState::new(
            "https://example.com".to_string(),
            "/tmp/file.mp4".to_string(),
            500,
            1000,
        );
        assert_eq!(state.progress_pct(), 50.0);
    }

    #[test]
    fn test_resume_state_is_recent() {
        let state = ResumeState::new(
            "https://example.com".to_string(),
            "/tmp/file.mp4".to_string(),
            0,
            0,
        );
        assert!(state.is_recent());
    }
}
