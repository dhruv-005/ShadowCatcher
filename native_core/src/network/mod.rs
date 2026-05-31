// ============================================
// SHADOW CATCHER - Network Module
// Download management and connection handling
// ============================================

pub mod connection_pool;
pub mod downloader;
pub mod resume_handler;

pub use connection_pool::ConnectionPool;
pub use downloader::Downloader;
pub use resume_handler::ResumeHandler;

use serde::{Deserialize, Serialize};

// ─────────────────────────────────────────
// DOWNLOAD PROGRESS
// ─────────────────────────────────────────

/// Download progress information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DownloadProgress {
    /// Task ID
    pub task_id: String,
    /// Bytes downloaded so far
    pub bytes_downloaded: u64,
    /// Total bytes (0 if unknown)
    pub bytes_total: u64,
    /// Current speed in KB/s
    pub speed_kbps: u64,
    /// Estimated time remaining in seconds
    pub eta_secs: u64,
    /// Progress percentage [0.0, 100.0]
    pub percentage: f32,
}

impl DownloadProgress {
    pub fn new(task_id: String) -> Self {
        Self {
            task_id,
            bytes_downloaded: 0,
            bytes_total: 0,
            speed_kbps: 0,
            eta_secs: 0,
            percentage: 0.0,
        }
    }

    /// Update progress with new byte count
    pub fn update(
        &mut self,
        bytes_downloaded: u64,
        bytes_total: u64,
        speed_kbps: u64,
    ) {
        self.bytes_downloaded = bytes_downloaded;
        self.bytes_total = bytes_total;
        self.speed_kbps = speed_kbps;

        if bytes_total > 0 {
            self.percentage = bytes_downloaded as f32
                / bytes_total as f32
                * 100.0;

            if speed_kbps > 0 {
                let remaining_bytes = bytes_total
                    .saturating_sub(bytes_downloaded);
                let remaining_kb = remaining_bytes as f64 / 1024.0;
                self.eta_secs = (remaining_kb / speed_kbps as f64) as u64;
            }
        }
    }

    /// Format bytes as human readable string
    pub fn format_bytes(bytes: u64) -> String {
        if bytes >= 1024 * 1024 * 1024 {
            format!("{:.1} GB", bytes as f64 / 1024.0 / 1024.0 / 1024.0)
        } else if bytes >= 1024 * 1024 {
            format!("{:.1} MB", bytes as f64 / 1024.0 / 1024.0)
        } else if bytes >= 1024 {
            format!("{:.1} KB", bytes as f64 / 1024.0)
        } else {
            format!("{} B", bytes)
        }
    }

    /// Format ETA as human readable string
    pub fn format_eta(&self) -> String {
        if self.eta_secs == 0 {
            return "Unknown".to_string();
        }
        let hours   = self.eta_secs / 3600;
        let minutes = (self.eta_secs % 3600) / 60;
        let seconds = self.eta_secs % 60;

        if hours > 0 {
            format!("{:02}:{:02}:{:02}", hours, minutes, seconds)
        } else {
            format!("{:02}:{:02}", minutes, seconds)
        }
    }
}

// ─────────────────────────────────────────
// HTTP RESPONSE INFO
// ─────────────────────────────────────────

/// Information extracted from HTTP response headers
#[derive(Debug, Clone, Default)]
pub struct ResponseInfo {
    pub content_length: Option<u64>,
    pub content_type: Option<String>,
    pub accept_ranges: bool,
    pub etag: Option<String>,
    pub last_modified: Option<String>,
    pub filename: Option<String>,
    pub is_redirect: bool,
    pub final_url: String,
    pub status_code: u16,
}

impl ResponseInfo {
    /// Check if server supports range requests (resumable)
    pub fn is_resumable(&self) -> bool {
        self.accept_ranges && self.content_length.is_some()
    }

    /// Extract filename from Content-Disposition header
    pub fn extract_filename(header: &str) -> Option<String> {
        // Content-Disposition: attachment; filename="video.mp4"
        header
            .split(';')
            .find(|s| s.trim().starts_with("filename"))
            .and_then(|s| s.split('=').nth(1))
            .map(|s| s.trim().trim_matches('"').to_string())
    }
}

// ─────────────────────────────────────────
// DOWNLOAD ERROR
// ─────────────────────────────────────────

/// Download-specific errors
#[derive(Debug, thiserror::Error)]
pub enum DownloadError {
    #[error("HTTP error: {status} - {message}")]
    HttpError { status: u16, message: String },

    #[error("Connection timeout after {secs}s")]
    Timeout { secs: u64 },

    #[error("Connection refused: {url}")]
    ConnectionRefused { url: String },

    #[error("SSL/TLS error: {0}")]
    TlsError(String),

    #[error("Too many redirects: {count}")]
    TooManyRedirects { count: u32 },

    #[error("File write error: {0}")]
    WriteError(String),

    #[error("Resume failed: offset {offset} exceeds file size {size}")]
    InvalidResumeOffset { offset: u64, size: u64 },

    #[error("Download cancelled")]
    Cancelled,

    #[error("Network error: {0}")]
    Network(String),
}
