// ============================================
// SHADOW CATCHER - App Configuration
// ============================================

use serde::{Deserialize, Serialize};

/// Main application configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppConfig {
    /// Path to ONNX model file
    pub onnx_model_path: String,
    /// Path to fallback hashes JSON
    pub fallback_hashes_path: String,
    /// Max concurrent downloads
    pub max_concurrent_downloads: usize,
    /// Download timeout in seconds
    pub download_timeout_secs: u64,
    /// Log level (trace/debug/info/warn/error)
    pub log_level: String,
    /// Log output directory
    pub log_dir: String,
    /// Download output directory
    pub download_dir: String,
    /// Enable stream cleaning
    pub enable_stream_cleaning: bool,
    /// Enable AI scanning
    pub enable_ai_scan: bool,
    /// Max download speed KB/s (0 = unlimited)
    pub max_speed_kbps: u64,
    /// RAM usage threshold for throttling (%)
    pub ram_threshold_pct: f32,
    /// Enable metadata stripping
    pub strip_metadata: bool,
    /// User agent string
    pub user_agent: String,
    /// Enable TLS verification
    pub verify_tls: bool,
    /// Connection pool size
    pub connection_pool_size: usize,
}

impl Default for AppConfig {
    fn default() -> Self {
        Self {
            onnx_model_path:          "assets/ai/shadow_brain.onnx".to_string(),
            fallback_hashes_path:     "assets/config/fallback_hashes.json".to_string(),
            max_concurrent_downloads: 3,
            download_timeout_secs:    3600,
            log_level:                "info".to_string(),
            log_dir:                  "logs".to_string(),
            download_dir:             "downloads".to_string(),
            enable_stream_cleaning:   true,
            enable_ai_scan:           true,
            max_speed_kbps:           0,
            ram_threshold_pct:        80.0,
            strip_metadata:           false,
            user_agent:               format!(
                "ShadowCatcher/{}",
                env!("CARGO_PKG_VERSION")
            ),
            verify_tls:               true,
            connection_pool_size:     8,
        }
    }
}

impl AppConfig {
    /// Load config from JSON string
    pub fn from_json(json: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(json)
    }

    /// Serialize config to JSON string
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }

    /// Validate configuration values
    pub fn validate(&self) -> Result<(), String> {
        if self.max_concurrent_downloads == 0 {
            return Err(
                "max_concurrent_downloads must be > 0".to_string()
            );
        }
        if self.download_timeout_secs == 0 {
            return Err(
                "download_timeout_secs must be > 0".to_string()
            );
        }
        if self.ram_threshold_pct < 10.0
            || self.ram_threshold_pct > 99.0
        {
            return Err(
                "ram_threshold_pct must be between 10 and 99".to_string()
            );
        }
        if self.onnx_model_path.is_empty() {
            return Err("onnx_model_path cannot be empty".to_string());
        }
        Ok(())
    }
}

// ─────────────────────────────────────────
// TESTS
// ─────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config_valid() {
        let config = AppConfig::default();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_config_serialization() {
        let config = AppConfig::default();
        let json = config.to_json().unwrap();
        let loaded = AppConfig::from_json(&json).unwrap();
        assert_eq!(config.max_concurrent_downloads,
                   loaded.max_concurrent_downloads);
    }

    #[test]
    fn test_invalid_concurrent_zero() {
        let mut config = AppConfig::default();
        config.max_concurrent_downloads = 0;
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_invalid_ram_threshold() {
        let mut config = AppConfig::default();
        config.ram_threshold_pct = 5.0;
        assert!(config.validate().is_err());
    }
}
