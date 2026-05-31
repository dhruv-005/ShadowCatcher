// ============================================
// SHADOW CATCHER - FFmpeg Bridge
// Interface with FFmpeg for media processing
// ============================================

use std::path::Path;
use std::process::{Command, Stdio};
use std::time::Instant;
use tracing::{info, warn, error, debug};

use crate::stream::StreamStats;
use crate::utils::error::{ShadowError, ShadowResult};

// ─────────────────────────────────────────
// FFMPEG CONFIG
// ─────────────────────────────────────────

/// FFmpeg processing configuration
#[derive(Debug, Clone)]
pub struct FfmpegConfig {
    /// Path to ffmpeg binary
    pub ffmpeg_path: String,
    /// Video codec to use for output
    pub video_codec: String,
    /// Audio codec to use for output
    pub audio_codec: String,
    /// Output format
    pub output_format: String,
    /// Video quality (CRF: 0-51, lower = better)
    pub video_crf: u8,
    /// Number of encoding threads
    pub threads: u8,
    /// Processing timeout in seconds
    pub timeout_secs: u64,
    /// Extra FFmpeg arguments
    pub extra_args: Vec<String>,
}

impl Default for FfmpegConfig {
    fn default() -> Self {
        Self {
            ffmpeg_path:   "ffmpeg".to_string(),
            video_codec:   "copy".to_string(),  // Copy = no re-encode (fast)
            audio_codec:   "copy".to_string(),
            output_format: "mp4".to_string(),
            video_crf:     23,
            threads:       2,
            timeout_secs:  3600, // 1 hour max
            extra_args:    Vec::new(),
        }
    }
}

// ─────────────────────────────────────────
// MEDIA INFO
// ─────────────────────────────────────────

/// Information about a media file
#[derive(Debug, Default, Clone)]
pub struct MediaInfo {
    pub duration_secs: f64,
    pub video_codec: String,
    pub audio_codec: String,
    pub width: u32,
    pub height: u32,
    pub fps: f32,
    pub bitrate_kbps: u64,
    pub file_size_bytes: u64,
    pub format: String,
}

// ─────────────────────────────────────────
// FFMPEG BRIDGE
// ─────────────────────────────────────────

/// Bridge to FFmpeg for media stream processing
pub struct FfmpegBridge {
    config: FfmpegConfig,
    ffmpeg_available: bool,
}

impl FfmpegBridge {
    /// Create a new FFmpeg bridge
    pub fn new() -> Self {
        let ffmpeg_available = Self::check_ffmpeg_available("ffmpeg");
        if !ffmpeg_available {
            warn!("FFmpeg not found in PATH. Stream re-encoding disabled.");
        } else {
            info!("FFmpeg found and available");
        }

        Self {
            config: FfmpegConfig::default(),
            ffmpeg_available,
        }
    }

    /// Create with custom config
    pub fn with_config(config: FfmpegConfig) -> Self {
        let ffmpeg_available = Self::check_ffmpeg_available(&config.ffmpeg_path);
        Self { config, ffmpeg_available }
    }

    // ─────────────────────────────────────
    // PUBLIC API
    // ─────────────────────────────────────

    /// Process a DASH stream (MPD) through FFmpeg
    pub async fn process_dash(
        &self,
        mpd_url: &str,
        output_path: &str,
    ) -> ShadowResult<StreamStats> {
        if !self.ffmpeg_available {
            return Err(ShadowError::Stream(
                "FFmpeg not available for DASH processing".to_string()
            ));
        }

        info!("Processing DASH stream via FFmpeg: {}", mpd_url);
        let start = Instant::now();

        let args = self.build_dash_args(mpd_url, output_path);
        self.run_ffmpeg(&args)?;

        let elapsed = start.elapsed().as_millis() as u64;
        let file_size = std::fs::metadata(output_path)
            .map(|m| m.len())
            .unwrap_or(0);

        Ok(StreamStats {
            total_segments: 1,
            clean_segments: 1,
            total_bytes_written: file_size,
            total_bytes_received: file_size,
            processing_time_ms: elapsed,
            ..Default::default()
        })
    }

    /// Re-encode a media file through FFmpeg
    pub async fn reencode(
        &self,
        input_path: &str,
        output_path: &str,
    ) -> ShadowResult<StreamStats> {
        if !self.ffmpeg_available {
            return Err(ShadowError::Stream(
                "FFmpeg not available for re-encoding".to_string()
            ));
        }

        info!("Re-encoding: {} → {}", input_path, output_path);
        let start = Instant::now();

        let args = self.build_reencode_args(input_path, output_path);
        self.run_ffmpeg(&args)?;

        let elapsed = start.elapsed().as_millis() as u64;
        let output_size = std::fs::metadata(output_path)
            .map(|m| m.len())
            .unwrap_or(0);
        let input_size = std::fs::metadata(input_path)
            .map(|m| m.len())
            .unwrap_or(0);

        Ok(StreamStats {
            total_segments: 1,
            clean_segments: 1,
            total_bytes_received: input_size,
            total_bytes_written: output_size,
            bytes_saved: input_size.saturating_sub(output_size),
            processing_time_ms: elapsed,
            ..Default::default()
        })
    }

    /// Get media file information
    pub fn get_media_info(
        &self,
        file_path: &str,
    ) -> ShadowResult<MediaInfo> {
        if !self.ffmpeg_available {
            return Err(ShadowError::Stream(
                "FFmpeg not available".to_string()
            ));
        }

        // Use ffprobe for media info
        let ffprobe = self.config.ffmpeg_path
            .replace("ffmpeg", "ffprobe");

        let output = Command::new(&ffprobe)
            .args([
                "-v", "quiet",
                "-print_format", "json",
                "-show_format",
                "-show_streams",
                file_path,
            ])
            .output()
            .map_err(|e| ShadowError::Stream(
                format!("ffprobe failed: {}", e)
            ))?;

        if !output.status.success() {
            return Err(ShadowError::Stream(
                "ffprobe returned error".to_string()
            ));
        }

        let json_str = String::from_utf8_lossy(&output.stdout);
        self.parse_media_info(&json_str)
    }

    /// Strip metadata from media file
    pub async fn strip_metadata(
        &self,
        input_path: &str,
        output_path: &str,
    ) -> ShadowResult<()> {
        if !self.ffmpeg_available {
            return Err(ShadowError::Stream(
                "FFmpeg not available".to_string()
            ));
        }

        info!("Stripping metadata: {}", input_path);

        let args = vec![
            "-i".to_string(),
            input_path.to_string(),
            "-map_metadata".to_string(),
            "-1".to_string(),         // Remove all metadata
            "-c".to_string(),
            "copy".to_string(),        // No re-encode
            "-y".to_string(),
            output_path.to_string(),
        ];

        self.run_ffmpeg(&args)?;
        Ok(())
    }

    /// Check if FFmpeg is available
    pub fn is_available(&self) -> bool {
        self.ffmpeg_available
    }

    /// Get FFmpeg version string
    pub fn get_version(&self) -> Option<String> {
        Command::new(&self.config.ffmpeg_path)
            .arg("-version")
            .output()
            .ok()
            .and_then(|o| String::from_utf8(o.stdout).ok())
            .and_then(|s| {
                s.lines()
                    .next()
                    .map(|l| l.to_string())
            })
    }

    // ─────────────────────────────────────
    // ARGUMENT BUILDERS
    // ─────────────────────────────────────

    /// Build FFmpeg args for DASH processing
    fn build_dash_args(
        &self,
        mpd_url: &str,
        output_path: &str,
    ) -> Vec<String> {
        let mut args = vec![
            "-y".to_string(),              // Overwrite output
            "-i".to_string(),
            mpd_url.to_string(),
            "-c:v".to_string(),
            self.config.video_codec.clone(),
            "-c:a".to_string(),
            self.config.audio_codec.clone(),
            "-threads".to_string(),
            self.config.threads.to_string(),
            "-movflags".to_string(),
            "+faststart".to_string(),
        ];

        args.extend(self.config.extra_args.clone());
        args.push(output_path.to_string());
        args
    }

    /// Build FFmpeg args for re-encoding
    fn build_reencode_args(
        &self,
        input_path: &str,
        output_path: &str,
    ) -> Vec<String> {
        let mut args = vec![
            "-y".to_string(),
            "-i".to_string(),
            input_path.to_string(),
        ];

        if self.config.video_codec == "libx264" {
            args.extend([
                "-c:v".to_string(),
                "libx264".to_string(),
                "-crf".to_string(),
                self.config.video_crf.to_string(),
                "-preset".to_string(),
                "fast".to_string(),
            ]);
        } else {
            args.extend([
                "-c:v".to_string(),
                self.config.video_codec.clone(),
            ]);
        }

        args.extend([
            "-c:a".to_string(),
            self.config.audio_codec.clone(),
            "-threads".to_string(),
            self.config.threads.to_string(),
            "-movflags".to_string(),
            "+faststart".to_string(),
        ]);

        args.extend(self.config.extra_args.clone());
        args.push(output_path.to_string());
        args
    }

    // ─────────────────────────────────────
    // FFMPEG EXECUTION
    // ─────────────────────────────────────

    /// Run FFmpeg with given arguments
    fn run_ffmpeg(&self, args: &[String]) -> ShadowResult<()> {
        debug!(
            "Running: {} {}",
            self.config.ffmpeg_path,
            args.join(" ")
        );

        let mut command = Command::new(&self.config.ffmpeg_path);
        command
            .args(args)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        let output = command
            .output()
            .map_err(|e| ShadowError::Stream(
                format!("Failed to run FFmpeg: {}", e)
            ))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            error!("FFmpeg failed:\n{}", stderr);
            return Err(ShadowError::Stream(
                format!("FFmpeg error: {}", stderr.lines().last().unwrap_or("unknown"))
            ));
        }

        let stderr = String::from_utf8_lossy(&output.stderr);
        debug!("FFmpeg output:\n{}", stderr);

        Ok(())
    }

    // ─────────────────────────────────────
    // UTILITIES
    // ─────────────────────────────────────

    /// Check if FFmpeg binary is available
    fn check_ffmpeg_available(ffmpeg_path: &str) -> bool {
        Command::new(ffmpeg_path)
            .arg("-version")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    }

    /// Parse ffprobe JSON output into MediaInfo
    fn parse_media_info(&self, json: &str) -> ShadowResult<MediaInfo> {
        let mut info = MediaInfo::default();

        // Simple JSON parsing without serde
        // (avoid heavy dep for this utility function)

        if let Some(duration_str) = Self::extract_json_str(json, "duration") {
            info.duration_secs = duration_str.parse().unwrap_or(0.0);
        }

        if let Some(bitrate_str) = Self::extract_json_str(json, "bit_rate") {
            info.bitrate_kbps = bitrate_str.parse::<u64>().unwrap_or(0) / 1000;
        }

        if let Some(width_str) = Self::extract_json_str(json, "width") {
            info.width = width_str.parse().unwrap_or(0);
        }

        if let Some(height_str) = Self::extract_json_str(json, "height") {
            info.height = height_str.parse().unwrap_or(0);
        }

        if let Some(codec) = Self::extract_json_str(json, "codec_name") {
            if info.video_codec.is_empty() {
                info.video_codec = codec.to_string();
            }
        }

        Ok(info)
    }

    /// Extract a string value from JSON by key
    fn extract_json_str<'a>(json: &'a str, key: &str) -> Option<&'a str> {
        let search = format!("\"{}\":", key);
        let start = json.find(&search)? + search.len();
        let rest = json[start..].trim_start();

        if rest.starts_with('"') {
            // String value
            let inner = &rest[1..];
            let end = inner.find('"')?;
            Some(&inner[..end])
        } else {
            // Numeric value
            let end = rest.find(|c: char| !c.is_ascii_digit() && c != '.')?;
            Some(&rest[..end])
        }
    }
}

impl Default for FfmpegBridge {
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
    fn test_ffmpeg_bridge_creates() {
        let bridge = FfmpegBridge::new();
        // Just verify it creates without panic
        let _ = bridge.is_available();
    }

    #[test]
    fn test_build_dash_args_contains_input() {
        let bridge = FfmpegBridge::new();
        let args = bridge.build_dash_args(
            "https://example.com/stream.mpd",
            "/tmp/output.mp4",
        );
        assert!(args.contains(&"-i".to_string()));
        assert!(args.contains(&"https://example.com/stream.mpd".to_string()));
        assert!(args.contains(&"/tmp/output.mp4".to_string()));
    }

    #[test]
    fn test_build_reencode_args() {
        let bridge = FfmpegBridge::new();
        let args = bridge.build_reencode_args(
            "/tmp/input.mp4",
            "/tmp/output.mp4",
        );
        assert!(args.contains(&"-i".to_string()));
        assert!(args.contains(&"-y".to_string()));
    }

    #[test]
    fn test_extract_json_str_numeric() {
        let json = r#"{"width": 1920, "height": 1080}"#;
        let result = FfmpegBridge::extract_json_str(json, "width");
        assert_eq!(result, Some("1920"));
    }

    #[test]
    fn test_extract_json_str_string() {
        let json = r#"{"codec_name": "h264", "bit_rate": "5000"}"#;
        let result = FfmpegBridge::extract_json_str(json, "codec_name");
        assert_eq!(result, Some("h264"));
    }

    #[test]
    fn test_extract_json_str_missing() {
        let json = r#"{"width": 1920}"#;
        let result = FfmpegBridge::extract_json_str(json, "nonexistent");
        assert!(result.is_none());
    }
}
