// ============================================
// SHADOW CATCHER - Stream Cleaner Integration Tests
// ============================================

use shadow_core::stream::{
    StreamType,
    StreamSegment,
    StreamStats,
    packet_filter::{PacketFilter, FilterRule, RuleSeverity, FilterAction},
    output_writer::OutputWriter,
};

// ─────────────────────────────────────────
// STREAM TYPE TESTS
// ─────────────────────────────────────────

#[cfg(test)]
mod stream_type_tests {
    use super::*;

    #[test]
    fn test_hls_detection() {
        assert_eq!(
            StreamType::from_url("https://cdn.example.com/stream.m3u8"),
            StreamType::Hls
        );
    }

    #[test]
    fn test_dash_detection() {
        assert_eq!(
            StreamType::from_url("https://cdn.example.com/manifest.mpd"),
            StreamType::Dash
        );
    }

    #[test]
    fn test_mp4_progressive() {
        assert_eq!(
            StreamType::from_url("https://example.com/video.mp4"),
            StreamType::Progressive
        );
    }

    #[test]
    fn test_mkv_progressive() {
        assert_eq!(
            StreamType::from_url("https://example.com/video.mkv"),
            StreamType::Progressive
        );
    }

    #[test]
    fn test_rtmp_detection() {
        assert_eq!(
            StreamType::from_url("rtmp://live.example.com/stream"),
            StreamType::Rtmp
        );
    }

    #[test]
    fn test_unknown_url() {
        assert_eq!(
            StreamType::from_url("https://example.com/data"),
            StreamType::Unknown
        );
    }

    #[test]
    fn test_hls_is_streaming() {
        assert!(StreamType::Hls.is_streaming_protocol());
        assert!(StreamType::Dash.is_streaming_protocol());
        assert!(!StreamType::Progressive.is_streaming_protocol());
    }
}

// ─────────────────────────────────────────
// PACKET FILTER TESTS
// ─────────────────────────────────────────

#[cfg(test)]
mod packet_filter_tests {
    use super::*;

    fn filter() -> PacketFilter {
        PacketFilter::new()
    }

    #[test]
    fn test_clean_segment_passes() {
        let f = filter();
        let data = vec![0xAAu8; 188 * 10];
        let segment = StreamSegment::new(
            0,
            "https://example.com/seg0.ts".to_string(),
            5.0,
            data.clone(),
        );
        let result = f.filter_segment(segment).unwrap();
        assert!(result.is_clean);
    }

    #[test]
    fn test_pe_injection_blocked() {
        let f = filter();
        let mut data = vec![0u8; 100];
        data.extend_from_slice(b"MZ\x90\x00");
        data.extend_from_slice(&[0u8; 100]);

        let segment = StreamSegment::new(
            0,
            "https://example.com/seg0.ts".to_string(),
            5.0,
            data,
        );
        let result = f.filter_segment(segment).unwrap();
        assert!(!result.is_clean, "PE injection should block segment");
    }

    #[test]
    fn test_elf_injection_blocked() {
        let f = filter();
        let mut data = vec![0u8; 50];
        data.extend_from_slice(b"\x7fELF\x02\x01\x01\x00");
        data.extend_from_slice(&[0u8; 100]);

        let segment = StreamSegment::new(
            1,
            "https://example.com/seg1.ts".to_string(),
            5.0,
            data,
        );
        let result = f.filter_segment(segment).unwrap();
        assert!(!result.is_clean, "ELF injection should block segment");
    }

    #[test]
    fn test_powershell_blocked() {
        let f = filter();
        let data = b"video data powershell -enc aGVsbG8= more data"
            .to_vec();

        let segment = StreamSegment::new(
            2,
            "https://example.com/seg2.ts".to_string(),
            5.0,
            data,
        );
        let result = f.filter_segment(segment).unwrap();
        assert!(!result.is_clean);
    }

    #[test]
    fn test_clean_chunk_passes() {
        let f = filter();
        let data = vec![0x42u8; 1024];
        let result = f.filter_chunk(&data).unwrap();
        assert_eq!(result, data);
    }

    #[test]
    fn test_ad_marker_removed_from_chunk() {
        let f = filter();
        let data = b"#EXT-X-DISCONTINUITY\n".to_vec();
        let result = f.filter_chunk(&data).unwrap();
        assert!(
            !result.windows(20)
                .any(|w| w == b"#EXT-X-DISCONTINUITY"),
            "Ad marker should be removed"
        );
    }

    #[test]
    fn test_scan_bytes_returns_rules() {
        let f = filter();
        let data = b"MZ\x90\x00 test data";
        let triggered = f.scan_bytes(data);
        assert!(!triggered.is_empty());
        assert!(triggered.iter().any(|r| r.name == "PE_Header_Injection"));
    }

    #[test]
    fn test_segment_issue_recorded() {
        let f = filter();
        let mut data = vec![0u8; 50];
        data.extend_from_slice(b"MZ\x90\x00");
        data.extend_from_slice(&[0u8; 50]);

        let segment = StreamSegment::new(
            5,
            "https://example.com/bad.ts".to_string(),
            5.0,
            data,
        );
        let result = f.filter_segment(segment).unwrap();
        assert!(!result.issues.is_empty());
    }

    #[test]
    fn test_custom_rule_added() {
        let mut f = filter();
        let initial = f.rule_count();

        f.add_rule(FilterRule {
            name: "TestRule",
            pattern: b"\xDE\xAD\xBE\xEF",
            severity: RuleSeverity::High,
            action: FilterAction::BlockSegment,
        });

        assert_eq!(f.rule_count(), initial + 1);
    }

    #[test]
    fn test_disabled_filter() {
        let mut f = filter();
        f.set_enabled(false);

        let data = b"MZ\x90\x00 executable data".to_vec();
        let result = f.filter_chunk(&data).unwrap();
        // Should pass through unchanged when disabled
        assert_eq!(result, data);
    }

    #[test]
    fn test_multiple_segments() {
        let f = filter();

        for i in 0..10 {
            let data = vec![0xBBu8; 188 * 5];
            let segment = StreamSegment::new(
                i,
                format!("https://example.com/seg{}.ts", i),
                5.0,
                data,
            );
            let result = f.filter_segment(segment).unwrap();
            assert!(result.is_clean, "Segment {} should be clean", i);
        }
    }
}

// ─────────────────────────────────────────
// OUTPUT WRITER TESTS
// ─────────────────────────────────────────

#[cfg(test)]
mod output_writer_tests {
    use super::*;
    use tempfile::TempDir;

    fn tmp_path(dir: &TempDir, name: &str) -> String {
        dir.path().join(name).to_string_lossy().to_string()
    }

    #[test]
    fn test_writer_creates_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = tmp_path(&dir, "output.mp4");
        let writer = OutputWriter::new(&path).unwrap();
        assert!(writer.file_exists());
    }

    #[test]
    fn test_writer_writes_bytes() {
        let dir = tempfile::tempdir().unwrap();
        let path = tmp_path(&dir, "output.mp4");
        let writer = OutputWriter::new(&path).unwrap();

        writer.write_bytes(b"test data").unwrap();
        writer.finalize().unwrap();

        assert_eq!(writer.bytes_written(), 9);
    }

    #[test]
    fn test_writer_content_correct() {
        let dir = tempfile::tempdir().unwrap();
        let path = tmp_path(&dir, "output.mp4");
        let writer = OutputWriter::new(&path).unwrap();

        writer.write_bytes(b"hello ").unwrap();
        writer.write_bytes(b"world").unwrap();
        writer.finalize().unwrap();

        let content = std::fs::read(&path).unwrap();
        assert_eq!(content, b"hello world");
    }

    #[test]
    fn test_writer_creates_nested_dirs() {
        let dir = tempfile::tempdir().unwrap();
        let path = tmp_path(&dir, "a/b/c/output.mp4");
        let writer = OutputWriter::new(&path).unwrap();
        assert!(writer.file_exists());
    }

    #[test]
    fn test_writer_large_data() {
        let dir = tempfile::tempdir().unwrap();
        let path = tmp_path(&dir, "large.mp4");
        let writer = OutputWriter::new(&path).unwrap();

        let chunk = vec![0xAAu8; 1024 * 1024]; // 1MB
        for _ in 0..10 {
            writer.write_bytes(&chunk).unwrap();
        }
        writer.finalize().unwrap();

        assert_eq!(
            writer.bytes_written(),
            10 * 1024 * 1024
        );
    }

    #[test]
    fn test_writer_delete() {
        let dir = tempfile::tempdir().unwrap();
        let path = tmp_path(&dir, "delete_me.mp4");
        let writer = OutputWriter::new(&path).unwrap();
        assert!(writer.file_exists());

        writer.delete().unwrap();
        assert!(!writer.file_exists());
    }

    #[test]
    fn test_writer_empty_write() {
        let dir = tempfile::tempdir().unwrap();
        let path = tmp_path(&dir, "empty.mp4");
        let writer = OutputWriter::new(&path).unwrap();

        writer.write_bytes(b"").unwrap();
        writer.finalize().unwrap();
        assert_eq!(writer.bytes_written(), 0);
    }
}

// ─────────────────────────────────────────
// STREAM STATS TESTS
// ─────────────────────────────────────────

#[cfg(test)]
mod stream_stats_tests {
    use super::*;

    #[test]
    fn test_bytes_saved_pct() {
        let stats = StreamStats {
            total_bytes_received: 1000,
            bytes_saved: 100,
            ..Default::default()
        };
        assert!((stats.bytes_saved_pct() - 10.0).abs() < 0.01);
    }

    #[test]
    fn test_throughput_mbps() {
        let stats = StreamStats {
            total_bytes_written: 1024 * 1024,
            processing_time_ms: 1000,
            ..Default::default()
        };
        assert!((stats.throughput_mbps() - 1.0).abs() < 0.01);
    }

    #[test]
    fn test_zero_received_pct() {
        let stats = StreamStats::default();
        assert_eq!(stats.bytes_saved_pct(), 0.0);
    }

    #[test]
    fn test_zero_time_throughput() {
        let stats = StreamStats {
            total_bytes_written: 1000,
            processing_time_ms: 0,
            ..Default::default()
        };
        assert_eq!(stats.throughput_mbps(), 0.0);
    }
}
