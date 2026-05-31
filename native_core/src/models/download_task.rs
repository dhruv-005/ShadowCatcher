// ============================================
// SHADOW CATCHER - Download Task Model
// ============================================

use serde::{Deserialize, Serialize};
use uuid::Uuid;
use chrono::{DateTime, Utc};

// ─────────────────────────────────────────
// DOWNLOAD STATUS
// ─────────────────────────────────────────

/// Current status of a download task
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum DownloadStatus {
    /// Waiting in queue
    Queued,
    /// Actively downloading
    Downloading,
    /// Running security scan
    Scanning,
    /// Download complete
    Complete,
    /// Blocked due to threat
    Blocked,
    /// User cancelled
    Cancelled,
    /// Failed with error
    Failed,
    /// Paused by user
    Paused,
    /// Resuming after pause
    Resuming,
}

impl DownloadStatus {
    /// Check if status is terminal (no more state changes)
    pub fn is_terminal(&self) -> bool {
        matches!(
            self,
            Self::Complete | Self::Blocked
                | Self::Cancelled | Self::Failed
        )
    }

    /// Check if download is active
    pub fn is_active(&self) -> bool {
        matches!(
            self,
            Self::Downloading | Self::Scanning | Self::Resuming
        )
    }

    /// Human readable description
    pub fn description(&self) -> &'static str {
        match self {
            Self::Queued      => "Waiting in queue",
            Self::Downloading => "Downloading",
            Self::Scanning    => "Scanning for threats",
            Self::Complete    => "Download complete",
            Self::Blocked     => "Blocked - threat detected",
            Self::Cancelled   => "Cancelled",
            Self::Failed      => "Failed",
            Self::Paused      => "Paused",
            Self::Resuming    => "Resuming",
        }
    }
}

impl std::fmt::Display for DownloadStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.description())
    }
}

// ─────────────────────────────────────────
// DOWNLOAD TASK
// ─────────────────────────────────────────

/// Represents a single download task
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DownloadTask {
    /// Unique task identifier
    pub id: String,
    /// Source URL
    pub url: String,
    /// Output directory
    pub output_path: String,
    /// Output filename
    pub filename: String,
    /// Current status
    pub status: DownloadStatus,
    /// Progress [0.0, 1.0]
    pub progress: f32,
    /// Download speed in KB/s
    pub speed_kbps: u64,
    /// Total file size in bytes
    pub total_bytes: u64,
    /// Bytes downloaded so far
    pub downloaded_bytes: u64,
    /// Estimated time remaining in seconds
    pub eta_secs: u64,
    /// Error message if failed
    pub error: Option<String>,
    /// When task was created
    pub created_at: DateTime<Utc>,
    /// When download started
    pub started_at: Option<DateTime<Utc>>,
    /// When download completed
    pub completed_at: Option<DateTime<Utc>>,
    /// Scan result if available
    pub scan_verdict: Option<String>,
    /// Whether download supports resume
    pub is_resumable: bool,
    /// Number of retry attempts
    pub retry_count: u32,
    /// File MIME type
    pub mime_type: Option<String>,
}

impl DownloadTask {
    /// Create a new download task
    pub fn new(
        url: String,
        output_path: String,
        filename: String,
    ) -> Self {
        Self {
            id: Uuid::new_v4().to_string(),
            url,
            output_path,
            filename,
            status: DownloadStatus::Queued,
            progress: 0.0,
            speed_kbps: 0,
            total_bytes: 0,
            downloaded_bytes: 0,
            eta_secs: 0,
            error: None,
            created_at: Utc::now(),
            started_at: None,
            completed_at: None,
            scan_verdict: None,
            is_resumable: false,
            retry_count: 0,
            mime_type: None,
        }
    }

    /// Mark task as started
    pub fn mark_started(&mut self) {
        self.status = DownloadStatus::Downloading;
        self.started_at = Some(Utc::now());
    }

    /// Mark task as complete
    pub fn mark_complete(&mut self) {
        self.status = DownloadStatus::Complete;
        self.progress = 1.0;
        self.completed_at = Some(Utc::now());
        self.speed_kbps = 0;
        self.eta_secs = 0;
    }

    /// Mark task as failed
    pub fn mark_failed(&mut self, error: String) {
        self.status = DownloadStatus::Failed;
        self.error = Some(error);
        self.completed_at = Some(Utc::now());
    }

    /// Mark task as blocked by threat
    pub fn mark_blocked(&mut self, threat: String) {
        self.status = DownloadStatus::Blocked;
        self.scan_verdict = Some(threat);
        self.completed_at = Some(Utc::now());
    }

    /// Update download progress
    pub fn update_progress(
        &mut self,
        downloaded: u64,
        total: u64,
        speed_kbps: u64,
    ) {
        self.downloaded_bytes = downloaded;
        self.total_bytes = total;
        self.speed_kbps = speed_kbps;

        if total > 0 {
            self.progress = downloaded as f32 / total as f32;
        }

        if speed_kbps > 0 && total > downloaded {
            let remaining_kb = (total - downloaded) as f64 / 1024.0;
            self.eta_secs = (remaining_kb / speed_kbps as f64) as u64;
        }
    }

    /// Get full output file path
    pub fn full_output_path(&self) -> String {
        format!("{}/{}", self.output_path, self.filename)
    }

    /// Get download duration in seconds
    pub fn duration_secs(&self) -> Option<i64> {
        match (self.started_at, self.completed_at) {
            (Some(start), Some(end)) => {
                Some((end - start).num_seconds())
            }
            _ => None,
        }
    }

    /// Get average speed in KB/s
    pub fn average_speed_kbps(&self) -> u64 {
        if let Some(duration) = self.duration_secs() {
            if duration > 0 {
                return self.downloaded_bytes
                    / (duration as u64 * 1024);
            }
        }
        0
    }

    /// Check if task is in a terminal state
    pub fn is_complete(&self) -> bool {
        self.status.is_terminal()
    }

    /// Format total bytes as string
    pub fn format_total_size(&self) -> String {
        format_bytes(self.total_bytes)
    }

    /// Format downloaded bytes as string
    pub fn format_downloaded(&self) -> String {
        format_bytes(self.downloaded_bytes)
    }
}

/// Format bytes to human readable string
fn format_bytes(bytes: u64) -> String {
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

// ─────────────────────────────────────────
// TESTS
// ─────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn task() -> DownloadTask {
        DownloadTask::new(
            "https://example.com/video.mp4".to_string(),
            "/tmp".to_string(),
            "video.mp4".to_string(),
        )
    }

    #[test]
    fn test_task_has_unique_id() {
        let t1 = task();
        let t2 = task();
        assert_ne!(t1.id, t2.id);
    }

    #[test]
    fn test_initial_status_queued() {
        assert_eq!(task().status, DownloadStatus::Queued);
    }

    #[test]
    fn test_mark_started() {
        let mut t = task();
        t.mark_started();
        assert_eq!(t.status, DownloadStatus::Downloading);
        assert!(t.started_at.is_some());
    }

    #[test]
    fn test_mark_complete() {
        let mut t = task();
        t.mark_complete();
        assert_eq!(t.status, DownloadStatus::Complete);
        assert_eq!(t.progress, 1.0);
        assert!(t.completed_at.is_some());
    }

    #[test]
    fn test_mark_failed() {
        let mut t = task();
        t.mark_failed("Connection timeout".to_string());
        assert_eq!(t.status, DownloadStatus::Failed);
        assert!(t.error.is_some());
    }

    #[test]
    fn test_mark_blocked() {
        let mut t = task();
        t.mark_blocked("Trojan.Generic".to_string());
        assert_eq!(t.status, DownloadStatus::Blocked);
        assert!(t.scan_verdict.is_some());
    }

    #[test]
    fn test_update_progress() {
        let mut t = task();
        t.update_progress(500, 1000, 100);
        assert_eq!(t.progress, 0.5);
        assert_eq!(t.downloaded_bytes, 500);
        assert_eq!(t.speed_kbps, 100);
    }

    #[test]
    fn test_full_output_path() {
        let t = task();
        assert_eq!(t.full_output_path(), "/tmp/video.mp4");
    }

    #[test]
    fn test_status_is_terminal() {
        assert!(DownloadStatus::Complete.is_terminal());
        assert!(DownloadStatus::Failed.is_terminal());
        assert!(DownloadStatus::Blocked.is_terminal());
        assert!(!DownloadStatus::Downloading.is_terminal());
        assert!(!DownloadStatus::Queued.is_terminal());
    }

    #[test]
    fn test_format_bytes() {
        assert_eq!(format_bytes(1024), "1.0 KB");
        assert_eq!(format_bytes(1024 * 1024), "1.0 MB");
        assert_eq!(format_bytes(500), "500 B");
    }
}
