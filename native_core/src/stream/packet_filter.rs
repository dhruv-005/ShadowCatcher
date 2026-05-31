// ============================================
// SHADOW CATCHER - Packet Filter
// Filters malicious packets from media streams
// ============================================

use tracing::{debug, warn};
use crate::stream::StreamSegment;
use crate::utils::error::{ShadowError, ShadowResult};

// ─────────────────────────────────────────
// FILTER RULES
// ─────────────────────────────────────────

/// A single packet filter rule
#[derive(Debug, Clone)]
pub struct FilterRule {
    pub name: &'static str,
    pub pattern: &'static [u8],
    pub severity: RuleSeverity,
    pub action: FilterAction,
}

/// Severity of a filter rule match
#[derive(Debug, Clone, PartialEq)]
pub enum RuleSeverity {
    Critical,
    High,
    Medium,
    Low,
}

/// Action to take when rule matches
#[derive(Debug, Clone, PartialEq)]
pub enum FilterAction {
    /// Block entire segment
    BlockSegment,
    /// Remove matching bytes only
    RemoveBytes,
    /// Log only - no action
    LogOnly,
}

/// Known malicious byte patterns in media streams
const FILTER_RULES: &[FilterRule] = &[
    // ── Executable injections ──
    FilterRule {
        name: "PE_Header_Injection",
        pattern: b"MZ\x90\x00",
        severity: RuleSeverity::Critical,
        action: FilterAction::BlockSegment,
    },
    FilterRule {
        name: "ELF_Header_Injection",
        pattern: b"\x7fELF",
        severity: RuleSeverity::Critical,
        action: FilterAction::BlockSegment,
    },

    // ── Script injections ──
    FilterRule {
        name: "PowerShell_Injection",
        pattern: b"powershell -enc",
        severity: RuleSeverity::Critical,
        action: FilterAction::BlockSegment,
    },
    FilterRule {
        name: "CMD_Injection",
        pattern: b"cmd.exe /c",
        severity: RuleSeverity::Critical,
        action: FilterAction::BlockSegment,
    },
    FilterRule {
        name: "Shell_Injection",
        pattern: b"#!/bin/",
        severity: RuleSeverity::High,
        action: FilterAction::BlockSegment,
    },

    // ── Malware C2 patterns ──
    FilterRule {
        name: "Metasploit_Shellcode",
        pattern: b"\xfc\xe8\x82\x00\x00\x00",
        severity: RuleSeverity::Critical,
        action: FilterAction::BlockSegment,
    },
    FilterRule {
        name: "Cobalt_Strike_Beacon",
        pattern: b"\x4d\x5a\x90\x00\x03\x00\x00\x00\x04\x00",
        severity: RuleSeverity::Critical,
        action: FilterAction::BlockSegment,
    },

    // ── Ad injection patterns ──
    FilterRule {
        name: "HLS_Ad_Marker",
        pattern: b"#EXT-X-DISCONTINUITY",
        severity: RuleSeverity::Low,
        action: FilterAction::RemoveBytes,
    },
    FilterRule {
        name: "SCTE35_Ad_Cue",
        pattern: b"\xfc\x30",
        severity: RuleSeverity::Low,
        action: FilterAction::RemoveBytes,
    },

    // ── Known malicious MPEG-TS patterns ──
    FilterRule {
        name: "Invalid_TS_Sync",
        pattern: b"\x47\xff\xff",
        severity: RuleSeverity::Medium,
        action: FilterAction::RemoveBytes,
    },
];

// ─────────────────────────────────────────
// PACKET FILTER STATS
// ─────────────────────────────────────────

/// Statistics from packet filtering
#[derive(Debug, Default, Clone)]
pub struct FilterStats {
    pub packets_processed: u64,
    pub packets_blocked: u64,
    pub bytes_removed: u64,
    pub rules_triggered: Vec<String>,
}

// ─────────────────────────────────────────
// MPEGTS PACKET
// ─────────────────────────────────────────

/// MPEG-TS packet (188 bytes each)
const MPEGTS_PACKET_SIZE: usize = 188;
const MPEGTS_SYNC_BYTE: u8 = 0x47;

/// A parsed MPEG-TS packet
#[derive(Debug)]
struct MpegTsPacket<'a> {
    sync_byte: u8,
    pid: u16,
    payload: &'a [u8],
    is_valid: bool,
}

impl<'a> MpegTsPacket<'a> {
    fn parse(data: &'a [u8]) -> Option<Self> {
        if data.len() < MPEGTS_PACKET_SIZE {
            return None;
        }

        let sync_byte = data[0];
        let is_valid = sync_byte == MPEGTS_SYNC_BYTE;

        // PID is in bytes 1-2 (bits 13:0)
        let pid = ((data[1] as u16 & 0x1F) << 8) | data[2] as u16;

        Some(Self {
            sync_byte,
            pid,
            payload: &data[4..],
            is_valid,
        })
    }

    /// Check if this is a null packet (PID 0x1FFF)
    fn is_null_packet(&self) -> bool {
        self.pid == 0x1FFF
    }

    /// Check if PID is in valid range
    fn has_valid_pid(&self) -> bool {
        // PIDs 0-8191 are valid
        // PIDs 0x0002-0x000F are reserved
        self.pid <= 8191 && !(0x0002..=0x000F).contains(&self.pid)
    }
}

// ─────────────────────────────────────────
// PACKET FILTER
// ─────────────────────────────────────────

/// Filters malicious content from media stream packets
pub struct PacketFilter {
    rules: Vec<FilterRule>,
    enabled: bool,
}

impl PacketFilter {
    /// Create a new packet filter with all default rules
    pub fn new() -> Self {
        Self {
            rules: FILTER_RULES.to_vec(),
            enabled: true,
        }
    }

    /// Create with custom rules
    pub fn with_rules(rules: Vec<FilterRule>) -> Self {
        Self { rules, enabled: true }
    }

    // ─────────────────────────────────────
    // PUBLIC API
    // ─────────────────────────────────────

    /// Filter a complete stream segment
    pub fn filter_segment(
        &self,
        mut segment: StreamSegment,
    ) -> ShadowResult<StreamSegment> {
        if !self.enabled {
            return Ok(segment);
        }

        debug!("Filtering segment {}", segment.index);

        // Check for rule violations in raw bytes
        for rule in &self.rules {
            if self.contains_pattern(&segment.data, rule.pattern) {
                match rule.action {
                    FilterAction::BlockSegment => {
                        warn!(
                            "Segment {} blocked by rule '{}' ({})",
                            segment.index,
                            rule.name,
                            format!("{:?}", rule.severity)
                        );
                        segment.add_issue(format!(
                            "Blocked by rule: {}",
                            rule.name
                        ));
                        return Ok(segment);
                    }
                    FilterAction::RemoveBytes => {
                        segment.data = self.remove_pattern(
                            &segment.data,
                            rule.pattern,
                        );
                        debug!(
                            "Removed pattern '{}' from segment {}",
                            rule.name, segment.index
                        );
                    }
                    FilterAction::LogOnly => {
                        warn!(
                            "Suspicious pattern '{}' in segment {}",
                            rule.name, segment.index
                        );
                    }
                }
            }
        }

        // MPEG-TS specific filtering
        if self.looks_like_mpegts(&segment.data) {
            segment.data = self.filter_mpegts(&segment.data)?;
        }

        Ok(segment)
    }

    /// Filter a raw chunk of bytes
    pub fn filter_chunk(
        &self,
        chunk: &[u8],
    ) -> ShadowResult<Vec<u8>> {
        if !self.enabled {
            return Ok(chunk.to_vec());
        }

        let mut data = chunk.to_vec();

        for rule in &self.rules {
            if self.contains_pattern(&data, rule.pattern) {
                match rule.action {
                    FilterAction::BlockSegment => {
                        warn!("Chunk blocked by rule: {}", rule.name);
                        return Ok(Vec::new()); // Return empty chunk
                    }
                    FilterAction::RemoveBytes => {
                        data = self.remove_pattern(&data, rule.pattern);
                    }
                    FilterAction::LogOnly => {
                        warn!("Suspicious pattern in chunk: {}", rule.name);
                    }
                }
            }
        }

        Ok(data)
    }

    /// Scan bytes and return list of triggered rules
    pub fn scan_bytes(&self, data: &[u8]) -> Vec<&FilterRule> {
        self.rules
            .iter()
            .filter(|rule| self.contains_pattern(data, rule.pattern))
            .collect()
    }

    /// Add a custom filter rule
    pub fn add_rule(&mut self, rule: FilterRule) {
        self.rules.push(rule);
    }

    /// Enable or disable filtering
    pub fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
    }

    /// Get total number of rules
    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }

    // ─────────────────────────────────────
    // MPEGTS PROCESSING
    // ─────────────────────────────────────

    /// Check if data looks like MPEG-TS
    fn looks_like_mpegts(&self, data: &[u8]) -> bool {
        if data.len() < MPEGTS_PACKET_SIZE {
            return false;
        }
        // Check first byte and packet alignment
        data[0] == MPEGTS_SYNC_BYTE
            && data.len() % MPEGTS_PACKET_SIZE == 0
    }

    /// Filter MPEG-TS stream packet by packet
    fn filter_mpegts(&self, data: &[u8]) -> ShadowResult<Vec<u8>> {
        let mut output = Vec::with_capacity(data.len());
        let mut offset = 0;

        while offset + MPEGTS_PACKET_SIZE <= data.len() {
            let packet_data = &data[offset..offset + MPEGTS_PACKET_SIZE];

            if let Some(packet) = MpegTsPacket::parse(packet_data) {
                if !packet.is_valid {
                    // Replace with null packet
                    output.extend_from_slice(&self.null_packet());
                    debug!("Replaced invalid TS packet at offset {}", offset);
                } else if self.is_suspicious_pid(packet.pid) {
                    // Replace suspicious PIDs with null packets
                    output.extend_from_slice(&self.null_packet());
                    warn!(
                        "Replaced suspicious TS PID 0x{:04x} at offset {}",
                        packet.pid, offset
                    );
                } else {
                    // Check payload for malicious content
                    let has_malware = self.rules.iter().any(|rule| {
                        self.contains_pattern(packet.payload, rule.pattern)
                    });

                    if has_malware {
                        output.extend_from_slice(&self.null_packet());
                        warn!(
                            "Replaced malicious TS payload at offset {}",
                            offset
                        );
                    } else {
                        output.extend_from_slice(packet_data);
                    }
                }
            } else {
                // Invalid packet - include as-is (might be non-TS data)
                output.extend_from_slice(packet_data);
            }

            offset += MPEGTS_PACKET_SIZE;
        }

        // Append any remaining bytes
        if offset < data.len() {
            output.extend_from_slice(&data[offset..]);
        }

        Ok(output)
    }

    /// Create an MPEG-TS null packet (188 bytes)
    fn null_packet(&self) -> Vec<u8> {
        let mut packet = vec![0u8; MPEGTS_PACKET_SIZE];
        packet[0] = MPEGTS_SYNC_BYTE;
        packet[1] = 0x1F; // PID high byte for null packet
        packet[2] = 0xFF; // PID low byte for null packet
        packet[3] = 0x10; // Adaptation field control
        packet
    }

    /// Check if PID is suspicious
    fn is_suspicious_pid(&self, pid: u16) -> bool {
        // Reserved PIDs that shouldn't appear in normal streams
        matches!(pid, 0x0002..=0x000F)
    }

    // ─────────────────────────────────────
    // UTILITIES
    // ─────────────────────────────────────

    /// Check if data contains a byte pattern
    fn contains_pattern(&self, data: &[u8], pattern: &[u8]) -> bool {
        if pattern.is_empty() || data.len() < pattern.len() {
            return false;
        }
        data.windows(pattern.len()).any(|w| w == pattern)
    }

    /// Remove all occurrences of pattern from data
    fn remove_pattern(&self, data: &[u8], pattern: &[u8]) -> Vec<u8> {
        if pattern.is_empty() {
            return data.to_vec();
        }

        let mut result = Vec::with_capacity(data.len());
        let mut i = 0;

        while i < data.len() {
            if i + pattern.len() <= data.len()
                && &data[i..i + pattern.len()] == pattern
            {
                // Skip the pattern bytes
                i += pattern.len();
            } else {
                result.push(data[i]);
                i += 1;
            }
        }

        result
    }
}

impl Default for PacketFilter {
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

    fn filter() -> PacketFilter {
        PacketFilter::new()
    }

    #[test]
    fn test_filter_has_rules() {
        assert!(filter().rule_count() > 0);
    }

    #[test]
    fn test_clean_data_passes_through() {
        let data = vec![0u8; 100];
        let result = filter().filter_chunk(&data).unwrap();
        assert_eq!(result, data);
    }

    #[test]
    fn test_blocks_pe_header() {
        let mut data = vec![0u8; 50];
        data.extend_from_slice(b"MZ\x90\x00");
        data.extend_from_slice(&[0u8; 50]);

        let result = filter().filter_chunk(&data).unwrap();
        assert!(result.is_empty(), "PE injection should block chunk");
    }

    #[test]
    fn test_blocks_powershell() {
        let data = b"some data powershell -enc aGVsbG8= more".to_vec();
        let result = filter().filter_chunk(&data).unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn test_removes_ad_marker() {
        let data = b"#EXT-X-DISCONTINUITY\n".to_vec();
        let result = filter().filter_chunk(&data).unwrap();
        assert!(!result.windows(20).any(|w| w == b"#EXT-X-DISCONTINUITY"));
    }

    #[test]
    fn test_scan_returns_triggered_rules() {
        let data = b"MZ\x90\x00 some data";
        let rules = filter().scan_bytes(data);
        assert!(!rules.is_empty());
        assert!(rules.iter().any(|r| r.name == "PE_Header_Injection"));
    }

    #[test]
    fn test_disabled_filter_passes_all() {
        let mut f = filter();
        f.set_enabled(false);

        let data = b"MZ\x90\x00 executable data".to_vec();
        let result = f.filter_chunk(&data).unwrap();
        assert_eq!(result, data);
    }

    #[test]
    fn test_remove_pattern() {
        let f = filter();
        let data = b"hello EVIL world EVIL end".to_vec();
        let result = f.remove_pattern(&data, b"EVIL ");
        assert!(!result.windows(5).any(|w| w == b"EVIL "));
    }

    #[test]
    fn test_null_packet_size() {
        let packet = filter().null_packet();
        assert_eq!(packet.len(), MPEGTS_PACKET_SIZE);
        assert_eq!(packet[0], MPEGTS_SYNC_BYTE);
    }

    #[test]
    fn test_segment_filter_blocks_pe() {
        let mut data = vec![0u8; 100];
        data[50] = b'M';
        data[51] = b'Z';
        data[52] = 0x90;
        data[53] = 0x00;

        let segment = StreamSegment::new(
            0,
            "https://example.com/seg.ts".to_string(),
            5.0,
            data,
        );

        let result = filter().filter_segment(segment).unwrap();
        assert!(!result.is_clean);
    }

    #[test]
    fn test_add_custom_rule() {
        let mut f = filter();
        let initial_count = f.rule_count();

        f.add_rule(FilterRule {
            name: "CustomRule",
            pattern: b"\xDE\xAD\xBE\xEF",
            severity: RuleSeverity::High,
            action: FilterAction::BlockSegment,
        });

        assert_eq!(f.rule_count(), initial_count + 1);
    }
}
