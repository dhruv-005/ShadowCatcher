// ============================================
// SHADOW CATCHER - Models Module
// Shared data structures
// ============================================

pub mod download_task;
pub mod scan_result;
pub mod threat_report;

pub use download_task::{DownloadTask, DownloadStatus};
pub use scan_result::{ScanResult, ScanVerdict};
pub use threat_report::{ThreatReport, ThreatLevel};
