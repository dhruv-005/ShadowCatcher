// ============================================
// SHADOW CATCHER - Packet Filter Unit Tests
// ============================================

use shadow_core::stream::{
    StreamSegment,
    packet_filter::{
        PacketFilter,
        FilterRule,
        RuleSeverity,
        FilterAction,
    },
};

fn filter() -> PacketFilter {
    PacketFilter::new()
}

fn clean_segment(index: u64, size: usize) -> StreamSegment {
    StreamSegment::new(
        index,
        format!("https://example.com/seg{}.ts", index),
        5.0,
        vec![0xABu8; size],
    )
}

// ─────────────────────────────────────────
// INITIALIZATION TESTS
// ─────────────────────────────────────────

#[test]
fn test_filter_has_default_rules() {
    assert!(filter().rule_count() > 0);
}

#[test]
fn test_filter_enabled_by_default() {
    let mut f = filter();
    f.set_enabled(true);
    assert_eq!(f.rule_count(), filter().rule_count());
}

// ─────────────────────────────────────────
// CHUNK FILTERING TESTS
// ─────────────────────────────────────────

#[test]
fn test_clean_data_unchanged() {
    let f = filter();
    let data = vec![0x00u8, 0x01, 0x02, 0x03, 0x04];
    let result = f.filter_chunk(&data).unwrap();
    assert_eq!(result, data);
}

#[test]
fn test_empty_chunk_unchanged() {
    let f = filter();
    let result = f.filter_chunk(&[]).unwrap();
    assert!(result.is_empty());
}

#[test]
fn test_pe_header_blocks_chunk() {
    let f = filter();
    let mut data = vec![0x00u8; 100];
    data.extend_from_slice(b"MZ\x90\x00");
    data.extend_from_slice(&[0x00u8; 100]);
    let result = f.filter_chunk(&data).unwrap();
    assert!(result.is_empty(), "PE header should block chunk");
}

#[test]
fn test_elf_header_blocks_chunk() {
    let f = filter();
    let mut data = vec![0x00u8; 50];
    data.extend_from_slice(b"\x7fELF\x02\x01\x01\x00");
    let result = f.filter_chunk(&data).unwrap();
    assert!(result.is_empty(), "ELF header should block chunk");
}

#[test]
fn test_cmd_exe_blocks_chunk() {
    let f = filter();
    let data = b"run cmd.exe /c del /f /s *.txt".to_vec();
    let result = f.filter_chunk(&data).unwrap();
    assert!(result.is_empty());
}

#[test]
fn test_powershell_enc_blocks_chunk() {
    let f = filter();
    let data = b"data powershell -enc SQBFAFgA data".to_vec();
    let result = f.filter_chunk(&data).unwrap();
    assert!(result.is_empty());
}

#[test]
fn test_ad_marker_removed_not_blocked() {
    let f = filter();
    let data = b"valid ts data #EXT-X-DISCONTINUITY\n more data".to_vec();
    let result = f.filter_chunk(&data).unwrap();
    // Should not be empty - just have marker removed
    assert!(!result.is_empty());
    assert!(
        !result.windows(20)
            .any(|w| w == b"#EXT-X-DISCONTINUITY"),
        "Ad marker should be removed"
    );
}

#[test]
fn test_multiple_threats_blocked() {
    let f = filter();
    let mut data = b"MZ\x90\x00".to_vec();
    data.extend_from_slice(b"\x7fELF");
    let result = f.filter_chunk(&data).unwrap();
    assert!(result.is_empty());
}

#[test]
fn test_large_clean_chunk() {
    let f = filter();
    let data = vec![0xCCu8; 1024 * 1024]; // 1MB
    let result = f.filter_chunk(&data).unwrap();
    assert_eq!(result.len(), data.len());
}

// ─────────────────────────────────────────
// SEGMENT FILTERING TESTS
// ─────────────────────────────────────────

#[test]
fn test_clean_segment_passes() {
    let f = filter();
    let seg = clean_segment(0, 188 * 10);
    let result = f.filter_segment(seg).unwrap();
    assert!(result.is_clean);
    assert!(result.issues.is_empty());
}

#[test]
fn test_pe_segment_blocked() {
    let f = filter();
    let mut data = vec![0x00u8; 100];
    data.extend_from_slice(b"MZ\x90\x00");
    data.extend_from_slice(&[0x00u8; 100]);

    let seg = StreamSegment::new(
        1,
        "https://example.com/seg.ts".to_string(),
        5.0,
        data,
    );
    let result = f.filter_segment(seg).unwrap();
    assert!(!result.is_clean, "PE should block segment");
    assert!(!result.issues.is_empty());
}

#[test]
fn test_segment_index_preserved() {
    let f = filter();
    let seg = clean_segment(42, 1000);
    let result = f.filter_segment(seg).unwrap();
    assert_eq!(result.index, 42);
}

#[test]
fn test_segment_url_preserved() {
    let f = filter();
    let seg = clean_segment(0, 100);
    let url = seg.url.clone();
    let result = f.filter_segment(seg).unwrap();
    assert_eq!(result.url, url);
}

#[test]
fn test_multiple_segments_processed() {
    let f = filter();
    let results: Vec<_> = (0..5)
        .map(|i| {
            let seg = clean_segment(i, 500);
            f.filter_segment(seg).unwrap()
        })
        .collect();

    assert_eq!(results.len(), 5);
    assert!(results.iter().all(|r| r.is_clean));
}

// ─────────────────────────────────────────
// SCAN BYTES TESTS
// ─────────────────────────────────────────

#[test]
fn test_scan_pe_header() {
    let f = filter();
    let rules = f.scan_bytes(b"MZ\x90\x00 test");
    assert!(!rules.is_empty());
    assert!(rules.iter().any(|r| r.name == "PE_Header_Injection"));
}

#[test]
fn test_scan_clean_data() {
    let f = filter();
    let rules = f.scan_bytes(b"normal video data stream");
    assert!(rules.is_empty());
}

#[test]
fn test_scan_multiple_threats() {
    let f = filter();
    let data = b"MZ\x90\x00 powershell -enc test";
    let rules = f.scan_bytes(data);
    assert!(rules.len() >= 2);
}

// ─────────────────────────────────────────
// CUSTOM RULE TESTS
// ─────────────────────────────────────────

#[test]
fn test_add_block_rule() {
    let mut f = filter();
    let initial = f.rule_count();

    f.add_rule(FilterRule {
        name: "TestBlockRule",
        pattern: b"\xDE\xAD\xBE\xEF",
        severity: RuleSeverity::Critical,
        action: FilterAction::BlockSegment,
    });

    assert_eq!(f.rule_count(), initial + 1);

    let data = b"\xDE\xAD\xBE\xEF some data".to_vec();
    let result = f.filter_chunk(&data).unwrap();
    assert!(result.is_empty());
}

#[test]
fn test_add_remove_rule() {
    let mut f = filter();
    f.add_rule(FilterRule {
        name: "RemoveTest",
        pattern: b"REMOVE_ME",
        severity: RuleSeverity::Medium,
        action: FilterAction::RemoveBytes,
    });

    let data = b"keep this REMOVE_ME keep that".to_vec();
    let result = f.filter_chunk(&data).unwrap();
    assert!(!result.is_empty());
    assert!(
        !result.windows(9).any(|w| w == b"REMOVE_ME"),
        "Pattern should be removed"
    );
}

#[test]
fn test_add_log_only_rule() {
    let mut f = filter();
    f.add_rule(FilterRule {
        name: "LogOnlyTest",
        pattern: b"SUSPICIOUS",
        severity: RuleSeverity::Low,
        action: FilterAction::LogOnly,
    });

    let data = b"some SUSPICIOUS data here".to_vec();
    let result = f.filter_chunk(&data).unwrap();
    // Log only - data should pass through unchanged
    assert_eq!(result, data);
}

// ─────────────────────────────────────────
// ENABLE/DISABLE TESTS
// ─────────────────────────────────────────

#[test]
fn test_disabled_passes_everything() {
    let mut f = filter();
    f.set_enabled(false);

    let data = b"MZ\x90\x00 this is an executable".to_vec();
    let result = f.filter_chunk(&data).unwrap();
    assert_eq!(result, data, "Disabled filter should pass all");
}

#[test]
fn test_disabled_segment_passes() {
    let mut f = filter();
    f.set_enabled(false);

    let mut data = vec![0u8; 50];
    data.extend_from_slice(b"MZ\x90\x00");
    data.extend_from_slice(&[0u8; 50]);

    let seg = StreamSegment::new(
        0,
        "https://example.com/seg.ts".to_string(),
        5.0,
        data.clone(),
    );
    let result = f.filter_segment(seg).unwrap();
    assert!(
        result.is_clean,
        "Disabled filter segment should be clean"
    );
}

#[test]
fn test_reenable_filter() {
    let mut f = filter();
    f.set_enabled(false);
    f.set_enabled(true);

    let data = b"MZ\x90\x00 executable".to_vec();
    let result = f.filter_chunk(&data).unwrap();
    assert!(result.is_empty(), "Re-enabled filter should block");
}
