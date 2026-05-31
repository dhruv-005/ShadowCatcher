// ============================================
// SHADOW CATCHER - Header Parser
// Deep analysis of file header structure
// ============================================

use crate::triage::magic_bytes::FileType;

// ─────────────────────────────────────────
// HEADER ISSUES
// ─────────────────────────────────────────

/// Issues found during header analysis
#[derive(Debug, Default)]
pub struct HeaderIssues {
    pub issues: Vec<HeaderIssue>,
    pub threat_name: Option<String>,
    pub risk_score: f32,
}

/// Individual header issue
#[derive(Debug, Clone)]
pub struct HeaderIssue {
    pub severity: IssueSeverity,
    pub description: String,
    pub indicator: String,
}

/// Issue severity level
#[derive(Debug, Clone, PartialEq)]
pub enum IssueSeverity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

impl HeaderIssues {
    /// Check if any critical issues found
    pub fn is_critical(&self) -> bool {
        self.issues.iter().any(|i| {
            i.severity == IssueSeverity::Critical
        })
    }

    /// Check if any high severity issues
    pub fn has_high_severity(&self) -> bool {
        self.issues.iter().any(|i| {
            matches!(
                i.severity,
                IssueSeverity::Critical | IssueSeverity::High
            )
        })
    }

    /// Count issues by severity
    pub fn count_by_severity(
        &self,
        severity: &IssueSeverity,
    ) -> usize {
        self.issues
            .iter()
            .filter(|i| &i.severity == severity)
            .count()
    }

    /// Add an issue
    pub fn add(
        &mut self,
        severity: IssueSeverity,
        description: &str,
        indicator: &str,
    ) {
        self.issues.push(HeaderIssue {
            severity: severity.clone(),
            description: description.to_string(),
            indicator: indicator.to_string(),
        });

        // Update risk score
        let score = match severity {
            IssueSeverity::Critical => 1.0,
            IssueSeverity::High     => 0.8,
            IssueSeverity::Medium   => 0.5,
            IssueSeverity::Low      => 0.2,
            IssueSeverity::Info     => 0.0,
        };
        self.risk_score = self.risk_score.max(score);

        // Set threat name for critical issues
        if severity == IssueSeverity::Critical
            && self.threat_name.is_none()
        {
            self.threat_name = Some(indicator.to_string());
        }
    }
}

// ─────────────────────────────────────────
// SUSPICIOUS PATTERNS
// ─────────────────────────────────────────

/// Known suspicious byte patterns
const SUSPICIOUS_PATTERNS: &[(&[u8], &str, IssueSeverity)] = &[
    // Shellcode patterns
    (
        b"\x60\x89\xe5\x31\xd2",
        "Linux shellcode pattern",
        IssueSeverity::Critical,
    ),
    (
        b"\xfc\xe8\x82\x00\x00\x00",
        "Windows shellcode (Metasploit)",
        IssueSeverity::Critical,
    ),

    // Malware strings
    (
        b"cmd.exe /c",
        "Command injection attempt",
        IssueSeverity::High,
    ),
    (
        b"powershell -enc",
        "Encoded PowerShell execution",
        IssueSeverity::Critical,
    ),
    (
        b"powershell -e ",
        "Encoded PowerShell execution",
        IssueSeverity::Critical,
    ),
    (
        b"WScript.Shell",
        "WScript Shell object creation",
        IssueSeverity::High,
    ),
    (
        b"CreateObject(",
        "ActiveX object creation",
        IssueSeverity::Medium,
    ),
    (
        b"regsvr32",
        "RegSvr32 bypass technique",
        IssueSeverity::High,
    ),
    (
        b"mshta.exe",
        "MSHTA execution",
        IssueSeverity::High,
    ),
    (
        b"certutil.exe",
        "CertUtil abuse",
        IssueSeverity::High,
    ),
    (
        b"eval(base64_decode",
        "PHP base64 eval",
        IssueSeverity::Critical,
    ),
    (
        b"eval(",
        "JavaScript eval execution",
        IssueSeverity::Medium,
    ),
    (
        b"document.write(unescape",
        "Obfuscated JavaScript",
        IssueSeverity::High,
    ),
    (
        b"<script>eval",
        "Inline script eval",
        IssueSeverity::High,
    ),
    (
        b"fromCharCode",
        "JavaScript char obfuscation",
        IssueSeverity::Medium,
    ),
    (
        b"VirtualAlloc",
        "Memory allocation (shellcode)",
        IssueSeverity::High,
    ),
    (
        b"WriteProcessMemory",
        "Process injection attempt",
        IssueSeverity::Critical,
    ),
    (
        b"CreateRemoteThread",
        "Remote thread creation",
        IssueSeverity::Critical,
    ),
];

// ─────────────────────────────────────────
// HEADER PARSER
// ─────────────────────────────────────────

/// Analyzes file headers for malicious indicators
pub struct HeaderParser {
    suspicious_patterns: Vec<(&'static [u8], &'static str, IssueSeverity)>,
}

impl HeaderParser {
    /// Create a new header parser
    pub fn new() -> Self {
        Self {
            suspicious_patterns: SUSPICIOUS_PATTERNS.to_vec(),
        }
    }

    /// Analyze header bytes for issues
    pub fn analyze(
        &self,
        header: &[u8],
        file_type: &FileType,
    ) -> HeaderIssues {
        let mut issues = HeaderIssues::default();

        // Run all analysis passes
        self.check_suspicious_strings(header, &mut issues);
        self.check_pe_structure(header, file_type, &mut issues);
        self.check_elf_structure(header, file_type, &mut issues);
        self.check_entropy_anomalies(header, &mut issues);
        self.check_embedded_executables(header, file_type, &mut issues);
        self.check_polyglot(header, file_type, &mut issues);

        issues
    }

    // ─────────────────────────────────────
    // ANALYSIS PASSES
    // ─────────────────────────────────────

    /// Check for known suspicious string patterns
    fn check_suspicious_strings(
        &self,
        header: &[u8],
        issues: &mut HeaderIssues,
    ) {
        for (pattern, description, severity) in &self.suspicious_patterns {
            if self.contains_pattern(header, pattern) {
                issues.add(
                    severity.clone(),
                    description,
                    description,
                );
            }
        }
    }

    /// Analyze PE (Windows executable) structure
    fn check_pe_structure(
        &self,
        header: &[u8],
        file_type: &FileType,
        issues: &mut HeaderIssues,
    ) {
        if *file_type != FileType::PeExecutable {
            return;
        }

        if header.len() < 64 {
            issues.add(
                IssueSeverity::Medium,
                "PE header too small",
                "TruncatedPEHeader",
            );
            return;
        }

        // Check for valid DOS stub
        if &header[0..2] != b"MZ" {
            issues.add(
                IssueSeverity::Critical,
                "Invalid PE signature",
                "InvalidPESignature",
            );
            return;
        }

        // Check PE offset (at byte 60)
        if header.len() >= 64 {
            let pe_offset = u32::from_le_bytes([
                header[60], header[61],
                header[62], header[63],
            ]) as usize;

            // PE header should be within first 1MB
            if pe_offset > 0x100000 {
                issues.add(
                    IssueSeverity::High,
                    "Suspicious PE offset - possible corruption or evasion",
                    "SuspiciousPEOffset",
                );
            }

            // Check for PE signature at offset
            if pe_offset + 4 < header.len() {
                if &header[pe_offset..pe_offset + 4] != b"PE\x00\x00" {
                    issues.add(
                        IssueSeverity::Medium,
                        "PE signature not found at expected offset",
                        "MissingPESignature",
                    );
                }
            }
        }

        // Check for known PE packer signatures
        let packer_signatures: &[(&[u8], &str)] = &[
            (b"UPX0", "UPX packer (evasion)"),
            (b"UPX1", "UPX packer (evasion)"),
            (b"MPRESS", "MPRESS packer"),
            (b"Themida", "Themida protector"),
            (b"ASPack", "ASPack packer"),
        ];

        for (sig, name) in packer_signatures {
            if self.contains_pattern(header, sig) {
                issues.add(
                    IssueSeverity::Medium,
                    &format!("Packed executable: {}", name),
                    "PackedExecutable",
                );
            }
        }
    }

    /// Analyze ELF (Linux binary) structure
    fn check_elf_structure(
        &self,
        header: &[u8],
        file_type: &FileType,
        issues: &mut HeaderIssues,
    ) {
        if *file_type != FileType::ElfExecutable {
            return;
        }

        if header.len() < 16 {
            issues.add(
                IssueSeverity::Medium,
                "ELF header too small",
                "TruncatedELFHeader",
            );
            return;
        }

        // Check ELF magic
        if &header[0..4] != b"\x7fELF" {
            issues.add(
                IssueSeverity::Critical,
                "Invalid ELF magic bytes",
                "InvalidELFMagic",
            );
        }

        // ELF class (byte 4): 1=32bit, 2=64bit
        let elf_class = header[4];
        if elf_class != 1 && elf_class != 2 {
            issues.add(
                IssueSeverity::Medium,
                "Invalid ELF class byte",
                "InvalidELFClass",
            );
        }

        // ELF type (bytes 16-17)
        if header.len() >= 18 {
            let elf_type = u16::from_le_bytes([header[16], header[17]]);
            // Type 2 = executable, 3 = shared object, 4 = core
            if elf_type == 4 {
                issues.add(
                    IssueSeverity::High,
                    "ELF core dump file",
                    "ELFCoreDump",
                );
            }
        }
    }

    /// Check for entropy anomalies (encrypted/packed content)
    fn check_entropy_anomalies(
        &self,
        header: &[u8],
        issues: &mut HeaderIssues,
    ) {
        if header.len() < 64 {
            return;
        }

        let entropy = self.calculate_entropy(&header[..64.min(header.len())]);

        if entropy > 0.95 {
            issues.add(
                IssueSeverity::Medium,
                &format!(
                    "Very high entropy ({:.2}) - possibly encrypted/packed",
                    entropy
                ),
                "HighEntropy",
            );
        }
    }

    /// Check for executables embedded in other file types
    fn check_embedded_executables(
        &self,
        header: &[u8],
        file_type: &FileType,
        issues: &mut HeaderIssues,
    ) {
        // If it's not an executable, check if it contains MZ/ELF
        if *file_type == FileType::PeExecutable
            || *file_type == FileType::ElfExecutable
        {
            return;
        }

        // Look for MZ header after the first 4 bytes
        for i in 4..header.len().saturating_sub(2) {
            if &header[i..i + 2] == b"MZ" {
                issues.add(
                    IssueSeverity::High,
                    "PE executable embedded in non-executable file",
                    "EmbeddedPE",
                );
                break;
            }
        }

        // Look for ELF header
        for i in 4..header.len().saturating_sub(4) {
            if &header[i..i + 4] == b"\x7fELF" {
                issues.add(
                    IssueSeverity::High,
                    "ELF executable embedded in file",
                    "EmbeddedELF",
                );
                break;
            }
        }
    }

    /// Check for polyglot files (valid in multiple formats)
    fn check_polyglot(
        &self,
        header: &[u8],
        file_type: &FileType,
        issues: &mut HeaderIssues,
    ) {
        // PDF + JavaScript polyglot
        if *file_type == FileType::Pdf {
            if self.contains_pattern(header, b"<script") {
                issues.add(
                    IssueSeverity::High,
                    "PDF contains JavaScript",
                    "PDFJavaScript",
                );
            }
            if self.contains_pattern(header, b"/AA") {
                issues.add(
                    IssueSeverity::Medium,
                    "PDF with auto-action",
                    "PDFAutoAction",
                );
            }
        }

        // ZIP + executable (polyglot)
        if *file_type == FileType::Zip {
            if header.len() >= 2 && &header[0..2] == b"MZ" {
                issues.add(
                    IssueSeverity::Critical,
                    "File is both ZIP and PE executable (polyglot)",
                    "PolyglotZipPE",
                );
            }
        }
    }

    // ─────────────────────────────────────
    // UTILITIES
    // ─────────────────────────────────────

    /// Check if header contains a byte pattern
    fn contains_pattern(&self, data: &[u8], pattern: &[u8]) -> bool {
        if pattern.is_empty() || data.len() < pattern.len() {
            return false;
        }
        data.windows(pattern.len())
            .any(|window| window == pattern)
    }

    /// Calculate Shannon entropy of byte slice
    fn calculate_entropy(&self, data: &[u8]) -> f32 {
        if data.is_empty() {
            return 0.0;
        }

        let mut counts = [0u32; 256];
        for &byte in data {
            counts[byte as usize] += 1;
        }

        let len = data.len() as f32;
        let mut entropy = 0.0f32;

        for &count in &counts {
            if count > 0 {
                let p = count as f32 / len;
                entropy -= p * p.log2();
            }
        }

        entropy / 8.0 // Normalize to [0, 1]
    }
}

impl Default for HeaderParser {
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

    fn parser() -> HeaderParser {
        HeaderParser::new()
    }

    #[test]
    fn test_clean_png_no_issues() {
        let header = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00";
        let issues = parser().analyze(header, &FileType::Png);
        assert!(!issues.is_critical());
    }

    #[test]
    fn test_detects_powershell_encoded() {
        let header = b"some data powershell -enc aGVsbG8= more data";
        let issues = parser().analyze(header, &FileType::Unknown);
        assert!(issues.is_critical() || issues.has_high_severity());
    }

    #[test]
    fn test_detects_cmd_injection() {
        let header = b"prefix cmd.exe /c del * suffix";
        let issues = parser().analyze(header, &FileType::Unknown);
        assert!(issues.has_high_severity());
    }

    #[test]
    fn test_detects_wscript() {
        let header = b"var x = new WScript.Shell(); x.Run(";
        let issues = parser().analyze(header, &FileType::JavaScriptFile);
        assert!(!issues.issues.is_empty());
    }

    #[test]
    fn test_detects_eval_base64() {
        let header = b"<?php eval(base64_decode('aGVsbG8='));";
        let issues = parser().analyze(header, &FileType::PhpScript);
        assert!(issues.is_critical());
    }

    #[test]
    fn test_entropy_calculation() {
        let parser = parser();

        // All same byte = zero entropy
        let zero_entropy = parser.calculate_entropy(&[0u8; 256]);
        assert!(zero_entropy < 0.01);

        // Random bytes = high entropy
        let high_entropy_data: Vec<u8> = (0u8..=255).collect();
        let high_entropy = parser.calculate_entropy(&high_entropy_data);
        assert!(high_entropy > 0.9);
    }

    #[test]
    fn test_detects_embedded_pe_in_png() {
        let mut header = b"\x89PNG\r\n\x1a\n".to_vec();
        header.extend_from_slice(b"\x00" * 50);
        header.extend_from_slice(b"MZ\x90\x00");
        let issues = parser().analyze(&header, &FileType::Png);
        assert!(issues.has_high_severity());
    }

    #[test]
    fn test_issues_risk_score() {
        let mut issues = HeaderIssues::default();
        assert_eq!(issues.risk_score, 0.0);
        issues.add(IssueSeverity::Critical, "test", "test");
        assert_eq!(issues.risk_score, 1.0);
    }
}
