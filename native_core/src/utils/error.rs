// ============================================
// SHADOW CATCHER - Error Types
// ============================================

use thiserror::Error;

/// Result type for Shadow Catcher operations
pub type ShadowResult<T> = Result<T, ShadowError>;

/// All possible errors in Shadow Catcher
#[derive(Debug, Error)]
pub enum ShadowError {
    #[error("Network error: {0}")]
    Network(String),

    #[error("IO error: {0}")]
    Io(String),

    #[error("AI model error: {0}")]
    AI(String),

    #[error("Stream error: {0}")]
    Stream(String),

    #[error("Configuration error: {0}")]
    Config(String),

    #[error("Security: Threat detected in '{0}'")]
    ThreatDetected(String),

    #[error("Internal error: {0}")]
    Internal(String),

    #[error("FFmpeg error: {0}")]
    FFmpeg(String),

    #[error("Parse error: {0}")]
    Parse(String),

    #[error("Timeout after {secs}s")]
    Timeout { secs: u64 },

    #[error("Not found: {0}")]
    NotFound(String),

    #[error("Permission denied: {0}")]
    PermissionDenied(String),

    #[error("Cancelled")]
    Cancelled,
}

impl ShadowError {
    /// Check if error is recoverable (can retry)
    pub fn is_recoverable(&self) -> bool {
        matches!(
            self,
            Self::Network(_) | Self::Timeout { .. }
        )
    }

    /// Check if error is a security issue
    pub fn is_security_error(&self) -> bool {
        matches!(self, Self::ThreatDetected(_))
    }

    /// Get error category for logging
    pub fn category(&self) -> &'static str {
        match self {
            Self::Network(_)          => "network",
            Self::Io(_)               => "io",
            Self::AI(_)               => "ai",
            Self::Stream(_)           => "stream",
            Self::Config(_)           => "config",
            Self::ThreatDetected(_)   => "security",
            Self::Internal(_)         => "internal",
            Self::FFmpeg(_)           => "ffmpeg",
            Self::Parse(_)            => "parse",
            Self::Timeout { .. }      => "timeout",
            Self::NotFound(_)         => "not_found",
            Self::PermissionDenied(_) => "permission",
            Self::Cancelled           => "cancelled",
        }
    }
}

impl From<std::io::Error> for ShadowError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e.to_string())
    }
}

impl From<reqwest::Error> for ShadowError {
    fn from(e: reqwest::Error) -> Self {
        Self::Network(e.to_string())
    }
}

impl From<serde_json::Error> for ShadowError {
    fn from(e: serde_json::Error) -> Self {
        Self::Parse(e.to_string())
    }
}

// ─────────────────────────────────────────
// TESTS
// ─────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_network_error_is_recoverable() {
        let e = ShadowError::Network("timeout".to_string());
        assert!(e.is_recoverable());
    }

    #[test]
    fn test_threat_error_not_recoverable() {
        let e = ShadowError::ThreatDetected("virus.exe".to_string());
        assert!(!e.is_recoverable());
        assert!(e.is_security_error());
    }

    #[test]
    fn test_error_category() {
        assert_eq!(
            ShadowError::Network("err".to_string()).category(),
            "network"
        );
        assert_eq!(
            ShadowError::ThreatDetected("f".to_string()).category(),
            "security"
        );
    }

    #[test]
    fn test_error_display() {
        let e = ShadowError::ThreatDetected("evil.exe".to_string());
        assert!(e.to_string().contains("evil.exe"));
    }

    #[test]
    fn test_from_io_error() {
        let io_err = std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "file not found",
        );
        let shadow_err: ShadowError = io_err.into();
        assert!(matches!(shadow_err, ShadowError::Io(_)));
    }
}
