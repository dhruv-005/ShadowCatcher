// ============================================
// SHADOW CATCHER - Stream Cleaner
// Main coordinator for stream security pipeline
// ============================================

use std::sync::Arc;
use std::time::Instant;
use tokio::sync::mpsc;
use tracing::{info, warn, error, debug};

use crate::stream::{
    StreamType,
    StreamSegment,
    StreamStats,
    StreamProcessor,
    packet_filter::PacketFilter,
    ffmpeg_bridge::FfmpegBridge,
    output_writer::OutputWriter,
};
use crate::utils::error::{ShadowError, ShadowResult};

// ─────────────────────────────────────────
// STREAM CLEANER CONFIG
// ─────────────────────────────────────────

/// Configuration for stream cleaning
#[derive(Debug, Clone)]
pub struct StreamCleanerConfig {
    /// Enable packet-level filtering
    pub enable_packet_filter: bool,
    /// Enable FFmpeg processing
    pub enable_ffmpeg: bool,
    /// Maximum segment size to process (bytes)
    pub max_segment_size: usize,
    /// Number of parallel segment processors
    pub parallel_workers: usize,
    /// Timeout per segment in seconds
    pub segment_timeout_secs: u64,
    /// Block stream if threat detected
    pub block_on_threat: bool,
    /// Allow continuing after suspicious segment
    pub continue_on_suspicious: bool,
}

impl Default for StreamCleanerConfig {
    fn default() -> Self {
        Self {
            enable_packet_filter:   true,
            enable_ffmpeg:          true,
            max_segment_size:       50 * 1024 * 1024, // 50MB
            parallel_workers:       2,
            segment_timeout_secs:   30,
            block_on_threat:        true,
            continue_on_suspicious: true,
        }
    }
}

// ─────────────────────────────────────────
// HLS PLAYLIST PARSER
// ─────────────────────────────────────────

/// Parsed HLS playlist
#[derive(Debug)]
struct HlsPlaylist {
    segments: Vec<HlsSegmentInfo>,
    base_url: String,
    total_duration: f32,
}

/// Info about a single HLS segment
#[derive(Debug, Clone)]
struct HlsSegmentInfo {
    url: String,
    duration: f32,
    index: u64,
}

/// Parse an M3U8 HLS playlist
fn parse_hls_playlist(content: &str, base_url: &str) -> HlsPlaylist {
    let mut segments = Vec::new();
    let mut current_duration = 0.0f32;
    let mut index = 0u64;

    // Extract base URL (remove filename)
    let base = base_url
        .rsplitn(2, '/')
        .last()
        .unwrap_or(base_url);

    for line in content.lines() {
        let line = line.trim();

        if line.starts_with("#EXTINF:") {
            // Parse duration: #EXTINF:5.000,
            let duration_str = line
                .trim_start_matches("#EXTINF:")
                .split(',')
                .next()
                .unwrap_or("0");
            current_duration = duration_str.parse().unwrap_or(0.0);
        } else if !line.is_empty() && !line.starts_with('#') {
            // This is a segment URL
            let full_url = if line.starts_with("http") {
                line.to_string()
            } else {
                format!("{}/{}", base, line)
            };

            segments.push(HlsSegmentInfo {
                url: full_url,
                duration: current_duration,
                index,
            });

            index += 1;
            current_duration = 0.0;
        }
    }

    let total_duration = segments.iter().map(|s| s.duration).sum();

    HlsPlaylist {
        segments,
        base_url: base.to_string(),
        total_duration,
    }
}

// ─────────────────────────────────────────
// STREAM CLEANER
// ─────────────────────────────────────────

/// Main stream security processor
///
/// Handles HLS, DASH, and progressive streams.
/// Scans each segment for threats and assembles
/// a clean output file.
pub struct StreamCleaner {
    config: StreamCleanerConfig,
    packet_filter: Arc<PacketFilter>,
    ffmpeg_bridge: Arc<FfmpegBridge>,
}

impl StreamCleaner {
    /// Create a new stream cleaner with default config
    pub fn new() -> Self {
        Self::with_config(StreamCleanerConfig::default())
    }

    /// Create with custom config
    pub fn with_config(config: StreamCleanerConfig) -> Self {
        Self {
            packet_filter: Arc::new(PacketFilter::new()),
            ffmpeg_bridge: Arc::new(FfmpegBridge::new()),
            config,
        }
    }

    /// Clean a stream from URL and write to output path
    ///
    /// Main entry point called from api.rs
    pub async fn clean(
        &self,
        stream_url: &str,
        output_path: &str,
    ) -> ShadowResult<StreamStats> {
        let start = Instant::now();
        let stream_type = StreamType::from_url(stream_url);

        info!(
            "Starting stream clean: {} (type: {})",
            stream_url,
            stream_type.display_name()
        );

        let stats = match stream_type {
            StreamType::Hls => {
                self.clean_hls(stream_url, output_path).await?
            }
            StreamType::Progressive => {
                self.clean_progressive(stream_url, output_path).await?
            }
            StreamType::Dash => {
                self.clean_dash(stream_url, output_path).await?
            }
            _ => {
                // Fallback to progressive for unknown types
                warn!(
                    "Unknown stream type, treating as progressive: {}",
                    stream_url
                );
                self.clean_progressive(stream_url, output_path).await?
            }
        };

        let elapsed_ms = start.elapsed().as_millis() as u64;
        info!(
            "Stream clean complete: {} segments, {} bytes saved, {}ms",
            stats.total_segments,
            stats.bytes_saved,
            elapsed_ms,
        );

        Ok(stats)
    }

    // ─────────────────────────────────────
    // HLS STREAM PROCESSING
    // ─────────────────────────────────────

    /// Process an HLS (M3U8) stream
    async fn clean_hls(
        &self,
        playlist_url: &str,
        output_path: &str,
    ) -> ShadowResult<StreamStats> {
        info!("Processing HLS stream: {}", playlist_url);

        // Download playlist
        let playlist_content = self.fetch_text(playlist_url).await?;

        // Check if master playlist (contains variant streams)
        if playlist_content.contains("#EXT-X-STREAM-INF") {
            // Pick best quality variant
            let variant_url = self.pick_best_hls_variant(
                &playlist_content,
                playlist_url,
            )?;
            return Box::pin(self.clean_hls(&variant_url, output_path)).await;
        }

        // Parse media playlist
        let playlist = parse_hls_playlist(&playlist_content, playlist_url);

        info!(
            "HLS playlist: {} segments, {:.1}s total",
            playlist.segments.len(),
            playlist.total_duration,
        );

        let mut stats = StreamStats::default();
        stats.total_segments = playlist.segments.len() as u64;

        // Create output writer
        let writer = OutputWriter::new(output_path)?;
        let writer = Arc::new(writer);

        // Process segments
        let (tx, mut rx) = mpsc::channel::<ShadowResult<StreamSegment>>(
            self.config.parallel_workers * 2
        );

        // Spawn download + processing tasks
        let segments = playlist.segments.clone();
        let filter = Arc::clone(&self.packet_filter);
        let config = self.config.clone();
        let tx_clone = tx.clone();

        tokio::spawn(async move {
            for seg_info in segments {
                let filter = Arc::clone(&filter);
                let tx = tx_clone.clone();
                let config = config.clone();

                tokio::spawn(async move {
                    let result = Self::process_hls_segment(
                        seg_info.clone(),
                        filter,
                        config,
                    ).await;
                    let _ = tx.send(result).await;
                });
            }
            drop(tx_clone);
        });

        drop(tx);

        // Collect processed segments in order
        let mut segment_buffer: Vec<Option<StreamSegment>> =
            vec![None; playlist.segments.len()];

        while let Some(result) = rx.recv().await {
            match result {
                Ok(segment) => {
                    let idx = segment.index as usize;
                    if segment.is_clean {
                        stats.clean_segments += 1;
                        stats.total_bytes_written += segment.data.len() as u64;
                    } else {
                        stats.blocked_segments += 1;
                        stats.bytes_saved += segment.data.len() as u64;
                        warn!(
                            "Segment {} blocked: {:?}",
                            segment.index,
                            segment.issues
                        );
                    }
                    stats.total_bytes_received += segment.data.len() as u64;

                    if idx < segment_buffer.len() {
                        segment_buffer[idx] = Some(segment);
                    }
                }
                Err(e) => {
                    error!("Segment processing error: {}", e);
                    stats.blocked_segments += 1;
                }
            }
        }

        // Write segments in order
        for segment_opt in segment_buffer.into_iter().flatten() {
            if segment_opt.is_clean {
                writer.write_bytes(&segment_opt.data)?;
            }
        }

        writer.finalize()?;
        stats.duration_secs = playlist.total_duration;

        Ok(stats)
    }

    /// Process a single HLS segment
    async fn process_hls_segment(
        seg_info: crate::stream::HlsSegmentInfo,
        filter: Arc<PacketFilter>,
        config: StreamCleanerConfig,
    ) -> ShadowResult<StreamSegment> {
        // Download segment
        let data = Self::fetch_bytes_static(&seg_info.url).await?;

        let mut segment = StreamSegment::new(
            seg_info.index,
            seg_info.url,
            seg_info.duration,
            data,
        );

        // Size check
        if segment.data.len() > config.max_segment_size {
            segment.add_issue(format!(
                "Segment too large: {} bytes",
                segment.data.len()
            ));
            return Ok(segment);
        }

        // Run packet filter
        if config.enable_packet_filter {
            segment = filter.filter_segment(segment)?;
        }

        Ok(segment)
    }

    // ─────────────────────────────────────
    // PROGRESSIVE STREAM PROCESSING
    // ─────────────────────────────────────

    /// Process a progressive download stream
    async fn clean_progressive(
        &self,
        url: &str,
        output_path: &str,
    ) -> ShadowResult<StreamStats> {
        info!("Processing progressive stream: {}", url);

        let mut stats = StreamStats {
            total_segments: 1,
            ..Default::default()
        };

        // Download file in chunks
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(300))
            .build()
            .map_err(|e| ShadowError::Network(e.to_string()))?;

        let response = client
            .get(url)
            .send()
            .await
            .map_err(|e| ShadowError::Network(e.to_string()))?;

        let total_size = response.content_length().unwrap_or(0);
        info!("Progressive download: {} bytes total", total_size);

        let writer = OutputWriter::new(output_path)?;
        let mut bytes_received = 0u64;
        let mut stream = response.bytes_stream();

        use futures::StreamExt;
        while let Some(chunk_result) = stream.next().await {
            let chunk = chunk_result
                .map_err(|e| ShadowError::Network(e.to_string()))?;

            // Filter chunk
            let filtered = if self.config.enable_packet_filter {
                self.packet_filter.filter_chunk(&chunk)?
            } else {
                chunk.to_vec()
            };

            bytes_received += chunk.len() as u64;
            let bytes_written = filtered.len() as u64;
            let bytes_removed = chunk.len() as u64 - bytes_written;

            stats.total_bytes_received += chunk.len() as u64;
            stats.total_bytes_written += bytes_written;
            stats.bytes_saved += bytes_removed;

            writer.write_bytes(&filtered)?;
        }

        writer.finalize()?;
        stats.clean_segments = 1;

        info!(
            "Progressive complete: {} bytes received, {} saved",
            bytes_received,
            stats.bytes_saved,
        );

        Ok(stats)
    }

    // ─────────────────────────────────────
    // DASH STREAM PROCESSING
    // ─────────────────────────────────────

    /// Process a DASH (MPD) stream
    async fn clean_dash(
        &self,
        mpd_url: &str,
        output_path: &str,
    ) -> ShadowResult<StreamStats> {
        info!("Processing DASH stream: {}", mpd_url);

        // For DASH, we delegate to FFmpeg which handles
        // MPD parsing natively
        let stats = if self.config.enable_ffmpeg {
            self.ffmpeg_bridge
                .process_dash(mpd_url, output_path)
                .await?
        } else {
            // Fallback: treat as progressive
            self.clean_progressive(mpd_url, output_path).await?
        };

        Ok(stats)
    }

    // ─────────────────────────────────────
    // HLS VARIANT SELECTION
    // ─────────────────────────────────────

    /// Pick the best quality HLS variant stream
    fn pick_best_hls_variant(
        &self,
        master_content: &str,
        base_url: &str,
    ) -> ShadowResult<String> {
        let base = base_url
            .rsplitn(2, '/')
            .last()
            .unwrap_or(base_url);

        let mut best_bandwidth = 0u64;
        let mut best_url = String::new();
        let mut next_is_url = false;

        for line in master_content.lines() {
            let line = line.trim();

            if line.starts_with("#EXT-X-STREAM-INF:") {
                // Parse bandwidth
                let bandwidth = line
                    .split(',')
                    .find(|s| s.contains("BANDWIDTH="))
                    .and_then(|s| s.split('=').nth(1))
                    .and_then(|s| s.parse::<u64>().ok())
                    .unwrap_or(0);

                if bandwidth > best_bandwidth {
                    best_bandwidth = bandwidth;
                    next_is_url = true;
                }
            } else if next_is_url && !line.is_empty() && !line.starts_with('#') {
                best_url = if line.starts_with("http") {
                    line.to_string()
                } else {
                    format!("{}/{}", base, line)
                };
                next_is_url = false;
            }
        }

        if best_url.is_empty() {
            return Err(ShadowError::Stream(
                "No valid HLS variant found in master playlist".to_string()
            ));
        }

        info!(
            "Selected HLS variant: {} (bandwidth: {})",
            best_url, best_bandwidth
        );

        Ok(best_url)
    }

    // ─────────────────────────────────────
    // HTTP UTILITIES
    // ─────────────────────────────────────

    /// Fetch text content from URL
    async fn fetch_text(&self, url: &str) -> ShadowResult<String> {
        let client = reqwest::Client::new();
        client
            .get(url)
            .send()
            .await
            .map_err(|e| ShadowError::Network(e.to_string()))?
            .text()
            .await
            .map_err(|e| ShadowError::Network(e.to_string()))
    }

    /// Fetch bytes from URL (static for use in spawned tasks)
    async fn fetch_bytes_static(url: &str) -> ShadowResult<Vec<u8>> {
        let client = reqwest::Client::new();
        let bytes = client
            .get(url)
            .send()
            .await
            .map_err(|e| ShadowError::Network(e.to_string()))?
            .bytes()
            .await
            .map_err(|e| ShadowError::Network(e.to_string()))?;
        Ok(bytes.to_vec())
    }
}

impl Default for StreamCleaner {
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

    #[test]
    fn test_stream_type_from_url_hls() {
        let url = "https://example.com/stream/playlist.m3u8";
        assert_eq!(StreamType::from_url(url), StreamType::Hls);
    }

    #[test]
    fn test_stream_type_from_url_mp4() {
        let url = "https://example.com/video.mp4";
        assert_eq!(StreamType::from_url(url), StreamType::Progressive);
    }

    #[test]
    fn test_stream_type_from_url_dash() {
        let url = "https://example.com/stream.mpd";
        assert_eq!(StreamType::from_url(url), StreamType::Dash);
    }

    #[test]
    fn test_parse_hls_playlist() {
        let content = r#"
#EXTM3U
#EXT-X-VERSION:3
#EXT-X-TARGETDURATION:5
#EXTINF:5.000,
segment0.ts
#EXTINF:5.000,
segment1.ts
#EXTINF:4.500,
segment2.ts
#EXT-X-ENDLIST
"#;
        let playlist = parse_hls_playlist(content, "https://example.com/stream");
        assert_eq!(playlist.segments.len(), 3);
        assert_eq!(playlist.segments[0].duration, 5.0);
        assert_eq!(playlist.segments[2].duration, 4.5);
        assert!((playlist.total_duration - 14.5).abs() < 0.01);
    }

    #[test]
    fn test_stream_cleaner_creates() {
        let cleaner = StreamCleaner::new();
        assert!(cleaner.config.enable_packet_filter);
    }

    #[test]
    fn test_stream_stats_bytes_saved_pct() {
        let stats = StreamStats {
            total_bytes_received: 1000,
            bytes_saved: 200,
            ..Default::default()
        };
        assert!((stats.bytes_saved_pct() - 20.0).abs() < 0.01);
    }

    #[test]
    fn test_stream_stats_throughput() {
        let stats = StreamStats {
            total_bytes_written: 1024 * 1024, // 1MB
            processing_time_ms: 1000,         // 1 second
            ..Default::default()
        };
        assert!((stats.throughput_mbps() - 1.0).abs() < 0.01);
    }

    #[test]
    fn test_stream_segment_add_issue() {
        let mut seg = StreamSegment::new(
            0,
            "https://example.com/seg0.ts".to_string(),
            5.0,
            vec![0u8; 100],
        );
        assert!(seg.is_clean);
        seg.add_issue("TestIssue".to_string());
        assert!(!seg.is_clean);
        assert_eq!(seg.issues.len(), 1);
    }
}
