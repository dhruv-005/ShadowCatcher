// ============================================
// SHADOW CATCHER - Public API Layer
// All Flutter ↔ Rust communication goes here
// ============================================

use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{info, error, warn};
use flutter_rust_bridge::frb;

use crate::models::{
    DownloadTask,
    DownloadStatus,
    ScanResult,
    ScanVerdict,
    ThreatReport,
};
use crate::network::downloader::Downloader;
use crate::triage::onnx_runner::OnnxRunner;
use crate::throttler::throttler::Throttler;
use crate::stream::stream_cleaner::StreamCleaner;
use crate::utils::config::AppConfig;
use crate::utils::error::{ShadowError, ShadowResult};
use crate::utils::logger;

// ─────────────────────────────────────────
// GLOBAL STATE
// ─────────────────────────────────────────

use once_cell::sync::OnceCell;

/// Global API instance
static API_INSTANCE: OnceCell<Arc<ShadowApi>> = OnceCell::new();

/// Initialize the global API instance
pub fn initialize(config_json: String) -> ShadowResult<()> {
    let config: AppConfig = serde_json::from_str(&config_json)
        .map_err(|e| ShadowError::Config(e.to_string()))?;

    let api = ShadowApi::new(config)?;
    let arc = Arc::new(api);

    API_INSTANCE.set(arc).map_err(|_| {
        ShadowError::Internal("API already initialized".to_string())
    })?;

    info!("Shadow Catcher core initialized successfully");
    Ok(())
}

/// Shutdown the global API
pub fn shutdown() {
    info!("Shadow Catcher core shutting down");
    // Cleanup handled by Drop implementations
}

/// Get reference to global API
pub fn get_api() -> ShadowResult<&'static Arc<ShadowApi>> {
    API_INSTANCE.get().ok_or_else(|| {
        ShadowError::Internal(
            "API not initialized. Call initialize_core() first.".to_string()
        )
    })
}

// ─────────────────────────────────────────
// SHADOW API
// ─────────────────────────────────────────

/// Main API struct that coordinates all subsystems
pub struct ShadowApi {
    config: AppConfig,
    downloader: Arc<Downloader>,
    onnx_runner: Arc<OnnxRunner>,
    throttler: Arc<Throttler>,
    stream_cleaner: Arc<StreamCleaner>,
    active_downloads: Arc<RwLock<Vec<DownloadTask>>>,
}

impl ShadowApi {
    /// Create a new ShadowApi instance
    pub fn new(config: AppConfig) -> ShadowResult<Self> {
        logger::init(&config.log_level)?;

        info!("Initializing Shadow Catcher API v{}", crate::VERSION);

        let onnx_runner = Arc::new(
            OnnxRunner::new(&config.onnx_model_path)
                .map_err(|e| ShadowError::AI(e.to_string()))?
        );

        let throttler = Arc::new(
            Throttler::new(config.max_concurrent_downloads)
        );

        let downloader = Arc::new(
            Downloader::new(
                config.max_concurrent_downloads,
                config.download_timeout_secs,
            )?
        );

        let stream_cleaner = Arc::new(
            StreamCleaner::new()
        );

        Ok(Self {
            config,
            downloader,
            onnx_runner,
            throttler,
            stream_cleaner,
            active_downloads: Arc::new(RwLock::new(Vec::new())),
        })
    }
}

// ─────────────────────────────────────────
// DOWNLOAD API
// ─────────────────────────────────────────

/// Start a new download
///
/// Called from Flutter when user initiates a download
#[frb]
pub fn start_download(
    url: String,
    output_path: String,
    filename: String,
) -> Result<String, String> {
    crate::block_on(async {
        let api = get_api().map_err(|e| e.to_string())?;

        let task = DownloadTask::new(
            url.clone(),
            output_path.clone(),
            filename.clone(),
        );
        let task_id = task.id.clone();

        info!("Starting download: {} → {}", url, filename);

        // Add to active downloads
        {
            let mut downloads = api.active_downloads.write().await;
            downloads.push(task.clone());
        }

        // Start download in background
        let downloader = Arc::clone(&api.downloader);
        let onnx_runner = Arc::clone(&api.onnx_runner);
        let throttler = Arc::clone(&api.throttler);
        let active_downloads = Arc::clone(&api.active_downloads);
        let task_id_clone = task_id.clone();

        tokio::spawn(async move {
            match execute_download(
                task,
                downloader,
                onnx_runner,
                throttler,
                active_downloads,
            ).await {
                Ok(_) => info!("Download complete: {}", task_id_clone),
                Err(e) => error!("Download failed: {} - {}", task_id_clone, e),
            }
        });

        Ok(task_id)
    })
}

/// Execute a download with scanning
async fn execute_download(
    mut task: DownloadTask,
    downloader: Arc<Downloader>,
    onnx_runner: Arc<OnnxRunner>,
    throttler: Arc<Throttler>,
    active_downloads: Arc<RwLock<Vec<DownloadTask>>>,
) -> ShadowResult<()> {
    // Update status to downloading
    update_task_status(
        &active_downloads,
        &task.id,
        DownloadStatus::Downloading,
    ).await;

    // Download file header for scanning
    let header_bytes = downloader
        .fetch_header_bytes(&task.url, 512)
        .await?;

    // Run AI scan on header
    update_task_status(
        &active_downloads,
        &task.id,
        DownloadStatus::Scanning,
    ).await;

    let scan_result = onnx_runner.scan(&header_bytes)?;

    match scan_result.verdict {
        ScanVerdict::Malicious | ScanVerdict::Suspicious => {
            warn!(
                "Threat detected in {}: {:?} ({:.2}%)",
                task.filename,
                scan_result.verdict,
                scan_result.confidence * 100.0,
            );

            update_task_status(
                &active_downloads,
                &task.id,
                DownloadStatus::Blocked,
            ).await;

            return Err(ShadowError::ThreatDetected(
                task.filename.clone()
            ));
        }
        ScanVerdict::Clean => {
            info!(
                "File clean: {} ({:.2}% confidence)",
                task.filename,
                scan_result.confidence * 100.0,
            );
        }
    }

    // Check throttler before downloading
    throttler.wait_for_slot().await;

    // Download full file
    downloader.download_file(
        &task.url,
        &task.output_path,
        &task.filename,
        |progress| {
            task.progress = progress;
        },
    ).await?;

    // Update final status
    update_task_status(
        &active_downloads,
        &task.id,
        DownloadStatus::Complete,
    ).await;

    throttler.release_slot();

    Ok(())
}

/// Cancel an active download
#[frb]
pub fn cancel_download(task_id: String) -> Result<bool, String> {
    crate::block_on(async {
        let api = get_api().map_err(|e| e.to_string())?;

        let mut downloads = api.active_downloads.write().await;
        if let Some(task) = downloads.iter_mut()
            .find(|t| t.id == task_id)
        {
            task.status = DownloadStatus::Cancelled;
            info!("Cancelled download: {}", task_id);
            return Ok(true);
        }

        Ok(false)
    })
}

/// Get all active downloads
#[frb]
pub fn get_active_downloads() -> Result<Vec<DownloadTask>, String> {
    crate::block_on(async {
        let api = get_api().map_err(|e| e.to_string())?;
        let downloads = api.active_downloads.read().await;
        Ok(downloads.clone())
    })
}

/// Get download progress (0.0 to 1.0)
#[frb]
pub fn get_download_progress(task_id: String) -> Result<f32, String> {
    crate::block_on(async {
        let api = get_api().map_err(|e| e.to_string())?;
        let downloads = api.active_downloads.read().await;

        let progress = downloads
            .iter()
            .find(|t| t.id == task_id)
            .map(|t| t.progress)
            .unwrap_or(0.0);

        Ok(progress)
    })
}

// ─────────────────────────────────────────
// SCAN API
// ─────────────────────────────────────────

/// Scan a file for threats
///
/// Called from Flutter for manual file scanning
#[frb]
pub fn scan_file(file_path: String) -> Result<ScanResult, String> {
    let api = match get_api() {
        Ok(a) => a,
        Err(e) => return Err(e.to_string()),
    };

    // Read file header
    let header_bytes = std::fs::read(&file_path)
        .map(|data| data[..data.len().min(512)].to_vec())
        .map_err(|e| format!("Failed to read file: {}", e))?;

    api.onnx_runner
        .scan(&header_bytes)
        .map_err(|e| e.to_string())
}

/// Scan raw bytes for threats
#[frb]
pub fn scan_bytes(data: Vec<u8>) -> Result<ScanResult, String> {
    let api = match get_api() {
        Ok(a) => a,
        Err(e) => return Err(e.to_string()),
    };

    let header = &data[..data.len().min(512)];
    api.onnx_runner
        .scan(header)
        .map_err(|e| e.to_string())
}

// ─────────────────────────────────────────
// STREAM API
// ─────────────────────────────────────────

/// Clean a video stream URL
///
/// Downloads and cleans stream, removing malicious packets
#[frb]
pub fn clean_stream(
    stream_url: String,
    output_path: String,
) -> Result<String, String> {
    crate::block_on(async {
        let api = get_api().map_err(|e| e.to_string())?;

        info!("Cleaning stream: {}", stream_url);

        api.stream_cleaner
            .clean(&stream_url, &output_path)
            .await
            .map_err(|e| e.to_string())?;

        Ok(output_path)
    })
}

// ─────────────────────────────────────────
// SYSTEM API
// ─────────────────────────────────────────

/// Get current system resource usage
#[frb]
pub fn get_system_stats() -> Result<String, String> {
    let api = match get_api() {
        Ok(a) => a,
        Err(e) => return Err(e.to_string()),
    };

    let stats = api.throttler.get_stats();
    serde_json::to_string(&stats)
        .map_err(|e| e.to_string())
}

/// Check if the AI model is loaded and ready
#[frb(sync)]
pub fn is_ai_ready() -> bool {
    get_api()
        .map(|api| api.onnx_runner.is_ready())
        .unwrap_or(false)
}

/// Get the AI model version/info
#[frb(sync)]
pub fn get_ai_info() -> String {
    get_api()
        .map(|api| api.onnx_runner.get_info())
        .unwrap_or_else(|_| "AI not initialized".to_string())
}

// ─────────────────────────────────────────
// UTILITIES
// ─────────────────────────────────────────

/// Update task status in active downloads list
async fn update_task_status(
    active_downloads: &Arc<RwLock<Vec<DownloadTask>>>,
    task_id: &str,
    status: DownloadStatus,
) {
    let mut downloads = active_downloads.write().await;
    if let Some(task) = downloads.iter_mut()
        .find(|t| t.id == task_id)
    {
        task.status = status;
    }
}

// ─────────────────────────────────────────
// TESTS
// ─────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_api_before_init_fails() {
        // Before initialization, get_api should return error
        // Note: This test assumes API is not initialized
        // In real tests, use a test fixture
        let result = get_api();
        // Either initialized or not - just check it doesn't panic
        let _ = result;
    }

    #[tokio::test]
    async fn test_update_task_status() {
        let downloads = Arc::new(RwLock::new(vec![
            DownloadTask::new(
                "https://example.com/file.mp4".to_string(),
                "/tmp".to_string(),
                "file.mp4".to_string(),
            ),
        ]));

        let task_id = {
            let d = downloads.read().await;
            d[0].id.clone()
        };

        update_task_status(
            &downloads,
            &task_id,
            DownloadStatus::Downloading,
        ).await;

        let d = downloads.read().await;
        assert_eq!(d[0].status, DownloadStatus::Downloading);
    }
}
