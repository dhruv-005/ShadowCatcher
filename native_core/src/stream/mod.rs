// ============================================
// SHADOW CATCHER - Stream Module
// Video/Audio stream processing pipeline
// ============================================

pub mod ffmpeg_bridge;
pub mod output_writer;
pub mod packet_filter;
pub mod stream_cleaner;

pub use ffmpeg_bridge::FfmpegBridge;
pub use output_writer::OutputWriter;
pub use packet_filter::PacketFilter;
pub use stream_cleaner::StreamCleaner;

use crate::utils::error::ShadowResult;

// ─────────────────────────────────────────
// STREAM TYPES
// ─────────────────────────────────────────

/// Type of media stream
#[derive(Debug, Clone, PartialEq)]
pub enum StreamType {
    /// HTTP Live Streaming (Apple)
    Hls,
    /// Dynamic Adaptive Streaming over HTTP (MPEG)
    Dash,
    /// Progressive download (direct file)
    Progressive,
    /// Real-Time Messaging Protocol
    Rtmp,
    /// Real-Time Streaming Protocol
    Rtsp,
    /// WebRTC stream
    WebRtc,
    /// Unknown stream type
    Unknown,
}

impl StreamType {
    /// Detect stream type from URL
    pub fn from_url(url: &str) -> Self {
        let url_lower = url.to_lowercase();

        if url_lower.ends_with(".m3u8")
            || url_lower.contains("/hls/")
        {
            return Self::Hls;
        }
        if url_lower.ends_with(".mpd")
            || url_lower.contains("/dash/")
        {
            return Self::Dash;
        }
        if url_lower.starts_with("rtmp://") {
            return Self::Rtmp;
        }
        if url_lower.starts_with("rtsp://") {
            return Self::Rtsp;
        }
        if url_lower.ends_with(".mp4")
            || url_lower.ends_with(".mkv")
            || url_lower.ends_with(".avi")
            || url_lower.ends_with(".webm")
        {
            return Self::Progressive;
        }

        Self::Unknown
    }

    /// Check if streaming protocol (vs direct download)
    pub fn is_streaming_protocol(&self) -> bool {
        matches!(self, Self::Hls | Self::Dash | Self::Rtmp | Self::Rtsp)
    }

    /// Human readable name
    pub fn display_name(&self) -> &'static str {
        match self {
            Self::Hls         => "HLS (HTTP Live Streaming)",
            Self::Dash        => "DASH (Dynamic Adaptive Streaming)",
            Self::Progressive => "Progressive Download",
            Self::Rtmp        => "RTMP",
            Self::Rtsp        => "RTSP",
            Self::WebRtc      => "WebRTC",
            Self::Unknown     => "Unknown",
        }
    }
}

// ─────────────────────────────────────────
// STREAM SEGMENT
// ─────────────────────────────────────────

/// A single segment of a media stream
#[derive(Debug, Clone)]
pub struct StreamSegment {
    /// Segment index in playlist
    pub index: u64,
    /// URL of this segment
    pub url: String,
    /// Duration in seconds
    pub duration: f32,
    /// Raw bytes of the segment
    pub data: Vec<u8>,
    /// Whether this segment passed security checks
    pub is_clean: bool,
    /// Detected issues in this segment
    pub issues: Vec<String>,
}

impl StreamSegment {
    pub fn new(
        index: u64,
        url: String,
        duration: f32,
        data: Vec<u8>,
    ) -> Self {
        Self {
            index,
            url,
            duration,
            data,
            is_clean: true,
            issues: Vec::new(),
        }
    }

    /// Mark segment as having an issue
    pub fn add_issue(&mut self, issue: String) {
        self.is_clean = false;
        self.issues.push(issue);
    }

    /// Get segment size in bytes
    pub fn size_bytes(&self) -> usize {
        self.data.len()
    }
}

// ─────────────────────────────────────────
// STREAM STATS
// ─────────────────────────────────────────

/// Statistics from stream processing
#[derive(Debug, Default, Clone)]
pub struct StreamStats {
    pub total_segments: u64,
    pub clean_segments: u64,
    pub blocked_segments: u64,
    pub total_bytes_received: u64,
    pub total_bytes_written: u64,
    pub bytes_saved: u64,
    pub duration_secs: f32,
    pub processing_time_ms: u64,
    pub average_segment_size: u64,
}

impl StreamStats {
    /// Calculate bytes saved percentage
    pub fn bytes_saved_pct(&self) -> f32 {
        if self.total_bytes_received == 0 {
            return 0.0;
        }
        self.bytes_saved as f32 / self.total_bytes_received as f32 * 100.0
    }

    /// Get throughput in MB/s
    pub fn throughput_mbps(&self) -> f32 {
        if self.processing_time_ms == 0 {
            return 0.0;
        }
        let bytes_per_ms = self.total_bytes_written as f32
            / self.processing_time_ms as f32;
        bytes_per_ms * 1000.0 / (1024.0 * 1024.0)
    }
}

// ─────────────────────────────────────────
// STREAM PIPELINE TRAIT
// ─────────────────────────────────────────

/// Trait for stream processing components
pub trait StreamProcessor: Send + Sync {
    /// Process a stream segment
    fn process_segment(
        &self,
        segment: StreamSegment,
    ) -> ShadowResult<StreamSegment>;

    /// Get processor name
    fn name(&self) -> &'static str;

    /// Check if processor is enabled
    fn is_enabled(&self) -> bool {
        true
    }
}
