// ============================================
// SHADOW CATCHER - Threat Report Model
// ============================================

use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};

// ─────────────────────────────────────────
// THREAT LEVEL
// ─────────────────────────────────────────

/// Severity level of a detected threat
#[derive(Debug, Clone, PartialEq, PartialOrd, Serialize, Deserialize)]
pub enum ThreatLevel {
    /// Informational - not a direct threat
    Info,
    /// Low risk - potentially unwanted
    Low,
    /// Medium risk - suspicious behavior
    Medium,
    /// High risk - likely malicious
    High,
    /// Critical - confirmed malware
    Critical,
}

impl ThreatLevel {
    pub fn display_name(&self) -> &'static str {
        match self {
            Self::Info     => "Info",
            Self::Low      => "Low",
            Self::Medium   => "Medium",
            Self::High     => "High",
            Self::Critical => "Critical",
        }
    }

    pub fn color(&self) -> &'static str {
        match self {
            Self::Info     => "#2196F3", // Blue
            Self::Low      => "#8BC34A", // Light Green
            Self::Medium   => "#FF9800", // Orange
            Self::High     => "#FF5722", // Deep Orange
            Self::Critical => "#F44336", // Red
        }
    }

    pub fn numeric_score(&self) -> u8 {
        match self {
            Self::Info     => 0,
            Self::Low      => 25,
            Self::Medium   => 50,
            Self::High     => 75,
            Self::Critical => 100,
        }
    }
}

// ─────────────────────────────────────────
// THREAT INDICATOR
// ─────────────────────────────────────────

/// A specific indicator of compromise
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatIndicator {
    pub indicator_type: String,
    pub value: String,
    pub description: String,
    pub confidence: f32,
}

impl ThreatIndicator {
    pub fn new(
        indicator_type: &str,
        value: &str,
        description: &str,
        confidence: f32,
    ) -> Self {
        Self {
            indicator_type: indicator_type.to_string(),
            value: value.to_string(),
            description: description.to_string(),
            confidence,
        }
    }
}

// ─────────────────────────────────────────
// THREAT REPORT
// ─────────────────────────────────────────

/// Detailed threat analysis report
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatReport {
    /// Unique report ID
    pub id: String,
    /// File that was scanned
    pub filename: String,
    /// Full file path
    pub file_path: String,
    /// File SHA-256 hash
    pub file_hash: String,
    /// File size in bytes
    pub file_size: u64,
    /// Threat level
    pub threat_level: ThreatLevel,
    /// Primary threat family name
    pub threat_family: Option<String>,
    /// Specific threat variant
    pub threat_variant: Option<String>,
    /// AI model confidence [0.0, 1.0]
    pub ai_confidence: f32,
    /// Detected file type
    pub detected_file_type: String,
    /// Original claimed file type (from extension)
    pub claimed_file_type: String,
    /// Whether extension was spoofed
    pub extension_spoofed: bool,
    /// Specific indicators found
    pub indicators: Vec<ThreatIndicator>,
    /// Recommended action
    pub recommended_action: String,
    /// When threat was detected
    pub detected_at: DateTime<Utc>,
    /// Download URL that was blocked
    pub source_url: Option<String>,
    /// Whether file was quarantined
    pub quarantined: bool,
}

impl ThreatReport {
    /// Create a new threat report
    pub fn new(
        filename: String,
        file_path: String,
        threat_level: ThreatLevel,
        ai_confidence: f32,
    ) -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            filename,
            file_path,
            file_hash: String::new(),
            file_size: 0,
            threat_level,
            threat_family: None,
            threat_variant: None,
            ai_confidence,
            detected_file_type: String::new(),
            claimed_file_type: String::new(),
            extension_spoofed: false,
            indicators: Vec::new(),
            recommended_action: String::new(),
            detected_at: Utc::now(),
            source_url: None,
            quarantined: false,
        }
    }

    /// Add a threat indicator
    pub fn add_indicator(&mut self, indicator: ThreatIndicator) {
        self.indicators.push(indicator);
    }

    /// Set threat family and variant
    pub fn set_threat_name(
        &mut self,
        family: &str,
        variant: Option<&str>,
    ) {
        self.threat_family = Some(family.to_string());
        self.threat_variant = variant.map(|s| s.to_string());
    }

    /// Get full threat name (Family.Variant)
    pub fn full_threat_name(&self) -> String {
        match (&self.threat_family, &self.threat_variant) {
            (Some(family), Some(variant)) => {
                format!("{}.{}", family, variant)
            }
            (Some(family), None) => family.clone(),
            _ => "Unknown Threat".to_string(),
        }
    }

    /// Set recommended action based on threat level
    pub fn set_recommended_action(&mut self) {
        self.recommended_action = match self.threat_level {
            ThreatLevel::Critical => {
                "BLOCK: Do not download. Delete any partial files. \
                 Report to security team.".to_string()
            }
            ThreatLevel::High => {
                "BLOCK: Download blocked. File may be harmful.".to_string()
            }
            ThreatLevel::Medium => {
                "WARN: Proceed with caution. Scan with antivirus.".to_string()
            }
            ThreatLevel::Low => {
                "INFO: Potentially unwanted content detected.".to_string()
            }
            ThreatLevel::Info => {
                "INFO: No action required.".to_string()
            }
        };
    }

    /// Check if this threat requires immediate blocking
    pub fn requires_blocking(&self) -> bool {
        self.threat_level >= ThreatLevel::High
    }

    /// Get confidence as percentage
    pub fn confidence_pct(&self) -> String {
        format!("{:.1}%", self.ai_confidence * 100.0)
    }

    /// Generate summary string
    pub fn summary(&self) -> String {
        format!(
            "[{}] {} - {} (confidence: {})",
            self.threat_level.display_name(),
            self.filename,
            self.full_threat_name(),
            self.confidence_pct(),
        )
    }

    /// Mark as quarantined
    pub fn mark_quarantined(&mut self) {
        self.quarantined = true;
    }
}

// ─────────────────────────────────────────
// TESTS
// ─────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn report() -> ThreatReport {
        ThreatReport::new(
            "malware.exe".to_string(),
            "/tmp/malware.exe".to_string(),
            ThreatLevel::Critical,
            0.98,
        )
    }

    #[test]
    fn test_report_has_id() {
        let r = report();
        assert!(!r.id.is_empty());
    }

    #[test]
    fn test_full_threat_name() {
        let mut r = report();
        r.set_threat_name("Trojan", Some("Win32.Generic"));
        assert_eq!(r.full_threat_name(), "Trojan.Win32.Generic");
    }

    #[test]
    fn test_full_threat_name_no_variant() {
        let mut r = report();
        r.set_threat_name("Ransomware", None);
        assert_eq!(r.full_threat_name(), "Ransomware");
    }

    #[test]
    fn test_requires_blocking_critical() {
        assert!(report().requires_blocking());
    }

    #[test]
    fn test_requires_blocking_low() {
        let r = ThreatReport::new(
            "suspicious.pdf".to_string(),
            "/tmp/suspicious.pdf".to_string(),
            ThreatLevel::Low,
            0.3,
        );
        assert!(!r.requires_blocking());
    }

    #[test]
    fn test_add_indicator() {
        let mut r = report();
        r.add_indicator(ThreatIndicator::new(
            "magic_bytes",
            "MZ header",
            "PE executable detected",
            0.99,
        ));
        assert_eq!(r.indicators.len(), 1);
    }

    #[test]
    fn test_set_recommended_action() {
        let mut r = report();
        r.set_recommended_action();
        assert!(!r.recommended_action.is_empty());
        assert!(r.recommended_action.contains("BLOCK"));
    }

    #[test]
    fn test_confidence_pct() {
        let r = report();
        assert_eq!(r.confidence_pct(), "98.0%");
    }

    #[test]
    fn test_threat_level_ordering() {
        assert!(ThreatLevel::Critical > ThreatLevel::High);
        assert!(ThreatLevel::High > ThreatLevel::Medium);
        assert!(ThreatLevel::Medium > ThreatLevel::Low);
        assert!(ThreatLevel::Low > ThreatLevel::Info);
    }

    #[test]
    fn test_mark_quarantined() {
        let mut r = report();
        assert!(!r.quarantined);
        r.mark_quarantined();
        assert!(r.quarantined);
    }
}
