// ============================================
// SHADOW CATCHER - Downloader
// Core download engine with progress tracking
// ============================================

use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use futures::StreamExt;
use reqwest::{Client, header};
use tracing::{info, warn, error, debug};

use crate::network::{
    DownloadProgress,
    ResponseInfo,
    connection_pool::ConnectionPool,
    resume_handler::ResumeHandler,
};
use crate::stream::output_writer::OutputWriter;
use crate::utils::error::{ShadowError, ShadowResult};

// ─────────────────────────────────────────
// DOWNLOADER CONFIG
// ─────────────────────────────────────────

/// Downloader configuration
#[derive(Debug, Clone)]
pub struct DownloaderConfig {
    pub max_concurrent: usize,
    pub timeout_secs: u64,
    pub connect_timeout_secs: u64,
    pub max_retries: u32,
    pub retry_delay_ms: u64,
    pub chunk_size: usize,
    pub user_agent: String,
    pub follow_redirects: bool,
    pub max_redirects: u32,
}

impl Default for DownloaderConfig {
    fn default() -> Self {
        Self {
            max_concurrent:       4,
            timeout_secs:         3600,
            connect_timeout_secs: 30,
            max_retries:          3,
            retry_delay_ms:       1000,
            chunk_size:           64 * 1024,   // 64KB chunks
            user_agent:           format!(
                "ShadowCatcher/{} (secure downloader)",
                env!("CARGO_PKG_VERSION")
            ),
            follow_redirects:     true,
            max_redirects:        10,
        }
    }
}

// ─────────────────────────────────────────
// DOWNLOADER
// ─────────────────────────────────────────

/// Core download engine
pub struct Downloader {
    config: DownloaderConfig,
    client: Client,
    pool: Arc<ConnectionPool>,
    resume_handler: Arc<ResumeHandler>,
}

impl Downloader {
    /// Create a new downloader
    pub fn new(
        max_concurrent: usize,
        timeout_secs: u64,
    ) -> ShadowResult<Self> {
        let config = DownloaderConfig {
            max_concurrent,
            timeout_secs,
            ..Default::default()
        };
        Self::with_config(config)
    }

    /// Create with custom config
    pub fn with_config(config: DownloaderConfig) -> ShadowResult<Self> {
        let client = Client::builder()
            .timeout(Duration::from_secs(config.timeout_secs))
            .connect_timeout(Duration::from_secs(
                config.connect_timeout_secs
            ))
            .user_agent(&config.user_agent)
            .redirect(reqwest::redirect::Policy::limited(
                config.max_redirects as usize
            ))
            .tcp_keepalive(Duration::from_secs(30))
            .pool_max_idle_per_host(config.max_concurrent)
            .build()
            .map_err(|e| ShadowError::Network(
                format!("Failed to build HTTP client: {}", e)
            ))?;

        Ok(Self {
            pool: Arc::new(ConnectionPool::new(config.max_concurrent)),
            resume_handler: Arc::new(ResumeHandler::new()),
            config,
            client,
        })
    }

    // ─────────────────────────────────────
    // PUBLIC API
    // ─────────────────────────────────────

    /// Fetch only the first N bytes of a URL (for scanning)
    pub async fn fetch_header_bytes(
        &self,
        url: &str,
        n: usize,
    ) -> ShadowResult<Vec<u8>> {
        debug!("Fetching {} header bytes from: {}", n, url);

        let response = self.client
            .get(url)
            .header(header::RANGE, format!("bytes=0-{}", n - 1))
            .send()
            .await
            .map_err(|e| ShadowError::Network(e.to_string()))?;

        if !response.status().is_success()
            && response.status().as_u16() != 206
        {
            return Err(ShadowError::Network(
                format!("HTTP {}: {}", response.status(), url)
            ));
        }

        let bytes = response
            .bytes()
            .await
            .map_err(|e| ShadowError::Network(e.to_string()))?;

        Ok(bytes[..bytes.len().min(n)].to_vec())
    }

    /// Get response info without downloading body
    pub async fn get_response_info(
        &self,
        url: &str,
    ) -> ShadowResult<ResponseInfo> {
        let response = self.client
            .head(url)
            .send()
            .await
            .map_err(|e| ShadowError::Network(e.to_string()))?;

        let status = response.status().as_u16();
        let headers = response.headers();

        let content_length = headers
            .get(header::CONTENT_LENGTH)
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.parse().ok());

        let content_type = headers
            .get(header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());

        let accept_ranges = headers
            .get(header::ACCEPT_RANGES)
            .and_then(|v| v.to_str().ok())
            .map(|s| s == "bytes")
            .unwrap_or(false);

        let etag = headers
            .get(header::ETAG)
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());

        let filename = headers
            .get(header::CONTENT_DISPOSITION)
            .and_then(|v| v.to_str().ok())
            .and_then(ResponseInfo::extract_filename);

        Ok(ResponseInfo {
            content_length,
            content_type,
            accept_ranges,
            etag,
            last_modified: None,
            filename,
            is_redirect: false,
            final_url: url.to_string(),
            status_code: status,
        })
    }

    /// Download a complete file
    pub async fn download_file(
        &self,
        url: &str,
        output_dir: &str,
        filename: &str,
        progress_callback: impl Fn(f32) + Send + 'static,
    ) -> ShadowResult<u64> {
        let output_path = format!("{}/{}", output_dir, filename);

        info!("Downloading: {} → {}", url, output_path);

        // Check for resume possibility
        let resume_offset = self.resume_handler
            .get_resume_offset(&output_path)
            .await
            .unwrap_or(0);

        if resume_offset > 0 {
            info!("Resuming download at offset: {}", resume_offset);
        }

        let mut retries = 0;
        loop {
            match self.download_with_resume(
                url,
                &output_path,
                resume_offset,
                &progress_callback,
            ).await {
                Ok(bytes) => {
                    info!("Download complete: {} ({} bytes)", filename, bytes);
                    self.resume_handler.clear(&output_path).await;
                    return Ok(bytes);
                }
                Err(e) => {
                    if retries >= self.config.max_retries {
                        error!(
                            "Download failed after {} retries: {}",
                            retries, e
                        );
                        return Err(e);
                    }
                    retries += 1;
                    warn!(
                        "Download error (retry {}/{}): {}",
                        retries, self.config.max_retries, e
                    );
                    tokio::time::sleep(Duration::from_millis(
                        self.config.retry_delay_ms * retries as u64
                    )).await;
                }
            }
        }
    }

    /// Download bytes from URL directly
    pub async fn download_bytes(
        &self,
        url: &str,
    ) -> ShadowResult<Vec<u8>> {
        let response = self.client
            .get(url)
            .send()
            .await
            .map_err(|e| ShadowError::Network(e.to_string()))?;

        if !response.status().is_success() {
            return Err(ShadowError::Network(
                format!("HTTP {}: {}", response.status(), url)
            ));
        }

        response.bytes()
            .await
            .map(|b| b.to_vec())
            .map_err(|e| ShadowError::Network(e.to_string()))
    }

    // ─────────────────────────────────────
    // INTERNAL DOWNLOAD
    // ─────────────────────────────────────

    /// Download file with resume support
    async fn download_with_resume(
        &self,
        url: &str,
        output_path: &str,
        resume_offset: u64,
        progress_callback: &impl Fn(f32),
    ) -> ShadowResult<u64> {
        // Build request
        let mut request = self.client.get(url);

        if resume_offset > 0 {
            request = request.header(
                header::RANGE,
                format!("bytes={}-", resume_offset),
            );
        }

        let response = request
            .send()
            .await
            .map_err(|e| ShadowError::Network(e.to_string()))?;

        let status = response.status();

        if !status.is_success() && status.as_u16() != 206 {
            return Err(ShadowError::Network(
                format!("HTTP error: {}", status)
            ));
        }

        // Get content info
        let total_size = response
            .content_length()
            .map(|len| len + resume_offset)
            .unwrap_or(0);

        // Open output file
        let writer = if resume_offset > 0 {
            OutputWriter::resume(output_path, resume_offset)?
        } else {
            OutputWriter::new(output_path)?
        };

        // Download stream
        let mut stream = response.bytes_stream();
        let mut bytes_downloaded = resume_offset;
        let mut last_progress_update = Instant::now();
        let mut speed_tracker = SpeedTracker::new();

        while let Some(chunk_result) = stream.next().await {
            let chunk = chunk_result
                .map_err(|e| ShadowError::Network(e.to_string()))?;

            writer.write_bytes(&chunk)?;
            bytes_downloaded += chunk.len() as u64;
            speed_tracker.add_bytes(chunk.len() as u64);

            // Save resume position
            self.resume_handler
                .save_progress(output_path, bytes_downloaded)
                .await;

            // Update progress
            if last_progress_update.elapsed() > Duration::from_millis(250) {
                let progress = if total_size > 0 {
                    bytes_downloaded as f32 / total_size as f32
                } else {
                    0.0
                };

                progress_callback(progress);
                last_progress_update = Instant::now();

                let speed = speed_tracker.speed_kbps();
                debug!(
                    "Progress: {:.1}% ({} KB/s)",
                    progress * 100.0,
                    speed,
                );
            }
        }

        writer.finalize()?;
        progress_callback(1.0);

        Ok(bytes_downloaded - resume_offset)
    }
}

// ─────────────────────────────────────────
// SPEED TRACKER
// ─────────────────────────────────────────

/// Tracks download speed over a sliding window
struct SpeedTracker {
    start: Instant,
    bytes: u64,
    window_start: Instant,
    window_bytes: u64,
}

impl SpeedTracker {
    fn new() -> Self {
        let now = Instant::now();
        Self {
            start: now,
            bytes: 0,
            window_start: now,
            window_bytes: 0,
        }
    }

    fn add_bytes(&mut self, bytes: u64) {
        self.bytes += bytes;
        self.window_bytes += bytes;

        // Reset window every second
        if self.window_start.elapsed() > Duration::from_secs(1) {
            self.window_bytes = bytes;
            self.window_start = Instant::now();
        }
    }

    fn speed_kbps(&self) -> u64 {
        let elapsed = self.window_start.elapsed().as_secs_f64();
        if elapsed < 0.001 {
            return 0;
        }
        (self.window_bytes as f64 / elapsed / 1024.0) as u64
    }

    fn average_speed_kbps(&self) -> u64 {
        let elapsed = self.start.elapsed().as_secs_f64();
        if elapsed < 0.001 {
            return 0;
        }
        (self.bytes as f64 / elapsed / 1024.0) as u64
    }
}

// ─────────────────────────────────────────
// TESTS
// ─────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_downloader_creates() {
        let downloader = Downloader::new(4, 30);
        assert!(downloader.is_ok());
    }

    #[test]
    fn test_speed_tracker() {
        let mut tracker = SpeedTracker::new();
        tracker.add_bytes(1024 * 100);
        let speed = tracker.speed_kbps();
        assert!(speed >= 0);
    }

    #[test]
    fn test_download_progress_update() {
        let mut progress = DownloadProgress::new("test".to_string());
        progress.update(500, 1000, 100);
        assert_eq!(progress.percentage, 50.0);
        assert_eq!(progress.bytes_downloaded, 500);
    }

    #[test]
    fn test_format_bytes() {
        assert_eq!(
            DownloadProgress::format_bytes(1024),
            "1.0 KB"
        );
        assert_eq!(
            DownloadProgress::format_bytes(1024 * 1024),
            "1.0 MB"
        );
        assert_eq!(
            DownloadProgress::format_bytes(500),
            "500 B"
        );
    }

    #[test]
    fn test_format_eta() {
        let mut p = DownloadProgress::new("test".to_string());
        p.eta_secs = 90;
        assert_eq!(p.format_eta(), "01:30");

        p.eta_secs = 3661;
        assert_eq!(p.format_eta(), "01:01:01");
    }

    #[test]
    fn test_response_info_resumable() {
        let info = ResponseInfo {
            content_length: Some(1000),
            accept_ranges: true,
            ..Default::default()
        };
        assert!(info.is_resumable());
    }

    #[test]
    fn test_response_info_not_resumable() {
        let info = ResponseInfo {
            content_length: None,
            accept_ranges: false,
            ..Default::default()
        };
        assert!(!info.is_resumable());
    }

    #[test]
    fn test_extract_filename() {
        let header = r#"attachment; filename="video.mp4""#;
        let filename = ResponseInfo::extract_filename(header);
        assert_eq!(filename, Some("video.mp4".to_string()));
    }
}
