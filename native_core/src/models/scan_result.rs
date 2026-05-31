// ============================================
// SHADOW CATCHER - Scan Result Model
// ============================================

use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};

// ─────────────────────────────────────────
// SCAN VERDICT
// ─────────────────────────────────────────

/// AI model verdict for a scanned file
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum ScanVerdict {
    /// File is clean - safe to download
    Clean,
    /// File is suspicious - warn user
    Suspicious,
    /// File is malicious - block download
    Malicious,
}

impl ScanVerdict {
    /// Check if file should be blocked
    pub fn should_block(&self) -> bool {
        matches!(self, Self::Malicious)
    }

    /// Check if user should be warned
    pub fn should_warn(&self) -> bool {
        matches!(self, Self::Suspicious | Self::Malicious)
    }

    /// Get color code for UI display
    pub fn color_code(&self) -> &'static str {
        match self {
            Self::Clean      => "#4CAF50", // Green
            Self::Suspicious => "#FF9800", // Orange
            Self::Malicious  => "#F44336", // Red
        }
    }

    /// Get icon name for UI
    pub fn icon_name(&self) -> &'static str {
        match self {
            Self::Clean      => "shield_check",
            Self::Suspicious => "shield_warning",
            Self::Malicious  => "shield_block",
        }
    }

    /// Human readable label
    pub fn label(&self) -> &'static str {
        match self {
            Self::Clean      => "Clean",
            Self::Suspicious => "Suspicious",
            Self::Malicious  => "Malicious",
        }
    }
}

impl std::fmt::Display for ScanVerdict {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.label())
    }
}

// ─────────────────────────────────────────
// SCAN RESULT
// ─────────────────────────────────────────

/// Result of a security scan
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResult {
    /// AI model verdict
    pub verdict: ScanVerdict,
    /// Confidence score [0.0, 1.0]
    pub confidence: f32,
    /// Threat name if detected
    pub threat_name: Option<String>,
    /// Detected file type
    pub detected_type: String,
    /// File size scanned in bytes
    pub file_size: u64,
    /// Time taken for scan in ms
    pub scan_duration_ms: u64,
    /// When scan was performed
    pub scanned_at: DateTime<Utc>,
    /// Scan engine version
    pub engine_version: String,
    /// Additional scan details
    pub details: Vec<ScanDetail>,
}

impl ScanResult {
    /// Create a clean scan result
    pub fn clean(
        confidence: f32,
        detected_type: String,
        file_size: u64,
        scan_duration_ms: u64,
    ) -> Self {
        Self {
            verdict: ScanVerdict::Clean,
            confidence,
            threat_name: None,
            detected_type,
            file_size,
            scan_duration_ms,
            scanned_at: Utc::now(),
            engine_version: env!("CARGO_PKG_VERSION").to_string(),
            details: Vec::new(),
        }
    }

    /// Create a malicious scan result
    pub fn malicious(
        confidence: f32,
        threat_name: String,
        detected_type: String,
        file_size: u64,
        scan_duration_ms: u64,
    ) -> Self {
        Self {
            verdict: ScanVerdict::Malicious,
            confidence,
            threat_name: Some(threat_name),
            detected_type,
            file_size,
            scan_duration_ms,
            scanned_at: Utc::now(),
            engine_version: env!("CARGO_PKG_VERSION").to_string(),
            details: Vec::new(),
        }
    }

    /// Check if file is safe to download
    pub fn is_safe(&self) -> bool {
        self.verdict == ScanVerdict::Clean
    }

    /// Get confidence as percentage string
    pub fn confidence_pct(&self) -> String {
        format!("{:.1}%", self.confidence * 100.0)
    }

    /// Add scan detail
    pub fn add_detail(
        &mut self,
        category: &str,
        description: &str,
    ) {
        self.details.push(ScanDetail {
            category: category.to_string(),
            description: description.to_string(),
        });
    }

    /// Get summary string for display
    pub fn summary(&self) -> String {
        match &self.verdict {
            ScanVerdict::Clean => format!(
                "✓ Clean ({} confidence)",
                self.confidence_pct()
            ),
            ScanVerdict::Suspicious => format!(
                "⚠ Suspicious ({} confidence)",
                self.confidence_pct()
            ),
            ScanVerdict::Malicious => format!(
                "✗ {} detected ({} confidence)",
                self.threat_name
                    .as_deref()
                    .unwrap_or("Malware"),
                self.confidence_pct()
            ),
        }
    }
}

/// Additional detail from scan
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanDetail {
    pub category: String,
    pub description: String,
}

// ─────────────────────────────────────────
// TESTS
// ─────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_clean_result() {
        let r = ScanResult::clean(0.97, "png".to_string(), 1024, 50);
        assert!(r.is_safe());
        assert_eq!(r.verdict, ScanVerdict::Clean);
        assert!(r.threat_name.is_none());
    }

    #[test]
    fn test_malicious_result() {
        let r = ScanResult::malicious(
            0.95,
            "Trojan.Generic".to_string(),
            "pe_executable".to_string(),
            2048,
            75,
        );
        assert!(!r.is_safe());
        assert!(r.verdict.should_block());
        assert_eq!(r.threat_name, Some("Trojan.Generic".to_string()));
    }

    #[test]
    fn test_confidence_pct() {
        let r = ScanResult::clean(0.975, "png".to_string(), 0, 0);
        assert_eq!(r.confidence_pct(), "97.5%");
    }

    #[test]
    fn test_verdict_should_block() {
        assert!(!ScanVerdict::Clean.should_block());
        assert!(!ScanVerdict::Suspicious.should_block());
        assert!(ScanVerdict::Malicious.should_block());
    }

    #[test]
    fn test_verdict_should_warn() {
        assert!(!ScanVerdict::Clean.should_warn());
        assert!(ScanVerdict::Suspicious.should_warn());
        assert!(ScanVerdict::Malicious.should_warn());
    }

    #[test]
    fn test_add_detail() {
        let mut r = ScanResult::clean(0.9, "png".to_string(), 0, 0);
        r.add_detail("entropy", "Low entropy - normal");
        assert_eq!(r.details.len(), 1);
    }

    #[test]
    fn test_summary_clean() {
        let r = ScanResult::clean(0.99, "png".to_string(), 0, 0);
        assert!(r.summary().contains("Clean"));
    }

    #[test]
    fn test_summary_malicious() {
        let r = ScanResult::malicious(
            0.95,
            "Trojan.Win32".to_string(),
            "exe".to_string(),
            0,
            0,
        );
        assert!(r.summary().contains("Trojan.Win32"));
    }
}
