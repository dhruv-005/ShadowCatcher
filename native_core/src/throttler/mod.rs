// ============================================
// SHADOW CATCHER - Throttler Module
// System resource management
// ============================================

pub mod ram_monitor;
pub mod tcp_controller;
pub mod throttler;

pub use ram_monitor::RamMonitor;
pub use tcp_controller::TcpController;
pub use throttler::Throttler;

use serde::{Deserialize, Serialize};

// ─────────────────────────────────────────
// RESOURCE LEVELS
// ─────────────────────────────────────────

/// System resource pressure level
#[derive(Debug, Clone, PartialEq, PartialOrd, Serialize, Deserialize)]
pub enum ResourceLevel {
    /// System is free - full speed
    Low,
    /// Moderate usage - slight reduction
    Medium,
    /// High usage - significant reduction
    High,
    /// Critical - pause new downloads
    Critical,
}

impl ResourceLevel {
    /// Get speed multiplier for this level [0.0, 1.0]
    pub fn speed_multiplier(&self) -> f32 {
        match self {
            Self::Low      => 1.0,
            Self::Medium   => 0.7,
            Self::High     => 0.3,
            Self::Critical => 0.0,
        }
    }

    /// Get max concurrent downloads for this level
    pub fn max_concurrent(&self) -> usize {
        match self {
            Self::Low      => 4,
            Self::Medium   => 2,
            Self::High     => 1,
            Self::Critical => 0,
        }
    }

    /// Human readable description
    pub fn description(&self) -> &'static str {
        match self {
            Self::Low      => "System free - full speed",
            Self::Medium   => "Moderate usage - reduced speed",
            Self::High     => "High usage - minimal speed",
            Self::Critical => "Critical - downloads paused",
        }
    }

    /// From RAM percentage
    pub fn from_ram_pct(ram_pct: f32) -> Self {
        if ram_pct >= 95.0 {
            Self::Critical
        } else if ram_pct >= 80.0 {
            Self::High
        } else if ram_pct >= 65.0 {
            Self::Medium
        } else {
            Self::Low
        }
    }

    /// From CPU percentage
    pub fn from_cpu_pct(cpu_pct: f32) -> Self {
        if cpu_pct >= 95.0 {
            Self::Critical
        } else if cpu_pct >= 80.0 {
            Self::High
        } else if cpu_pct >= 60.0 {
            Self::Medium
        } else {
            Self::Low
        }
    }
}

// ─────────────────────────────────────────
// SYSTEM STATS
// ─────────────────────────────────────────

/// Current system resource statistics
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SystemStats {
    pub ram_used_mb: u64,
    pub ram_total_mb: u64,
    pub ram_pct: f32,
    pub cpu_pct: f32,
    pub active_downloads: usize,
    pub resource_level: String,
    pub download_speed_kbps: u64,
    pub max_speed_kbps: u64,
}

impl SystemStats {
    pub fn ram_free_mb(&self) -> u64 {
        self.ram_total_mb.saturating_sub(self.ram_used_mb)
    }
}
