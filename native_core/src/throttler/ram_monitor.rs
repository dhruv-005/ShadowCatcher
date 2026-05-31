// ============================================
// SHADOW CATCHER - RAM Monitor
// Monitors system memory and CPU usage
// ============================================

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use sysinfo::{System, SystemExt, CpuExt};
use parking_lot::Mutex;
use tracing::debug;

// ─────────────────────────────────────────
// RAM MONITOR
// ─────────────────────────────────────────

/// Monitors system RAM and CPU usage
pub struct RamMonitor {
    system: Mutex<System>,
    cached_ram_pct: AtomicU64,
    cached_cpu_pct: AtomicU64,
}

impl RamMonitor {
    /// Create a new RAM monitor
    pub fn new() -> Self {
        let mut system = System::new_all();
        system.refresh_all();

        Self {
            system: Mutex::new(system),
            cached_ram_pct: AtomicU64::new(0),
            cached_cpu_pct: AtomicU64::new(0),
        }
    }

    // ─────────────────────────────────────
    // PUBLIC API
    // ─────────────────────────────────────

    /// Get RAM statistics
    ///
    /// Returns (ram_pct, ram_used_mb, ram_total_mb)
    pub fn get_ram_stats(&self) -> (f32, u64, u64) {
        let mut system = self.system.lock();
        system.refresh_memory();

        let used  = system.used_memory();    // bytes
        let total = system.total_memory();   // bytes

        let ram_pct = if total > 0 {
            used as f32 / total as f32 * 100.0
        } else {
            0.0
        };

        let used_mb  = used  / (1024 * 1024);
        let total_mb = total / (1024 * 1024);

        // Cache the value
        self.cached_ram_pct.store(
            (ram_pct * 100.0) as u64,
            Ordering::Relaxed,
        );

        debug!(
            "RAM: {:.1}% ({} MB / {} MB)",
            ram_pct, used_mb, total_mb
        );

        (ram_pct, used_mb, total_mb)
    }

    /// Get CPU usage percentage
    pub fn get_cpu_pct(&self) -> f32 {
        let mut system = self.system.lock();
        system.refresh_cpu();

        let cpus = system.cpus();
        if cpus.is_empty() {
            return 0.0;
        }

        let cpu_pct = cpus.iter()
            .map(|cpu| cpu.cpu_usage())
            .sum::<f32>() / cpus.len() as f32;

        self.cached_cpu_pct.store(
            (cpu_pct * 100.0) as u64,
            Ordering::Relaxed,
        );

        debug!("CPU: {:.1}%", cpu_pct);
        cpu_pct
    }

    /// Get cached RAM percentage (no system call)
    pub fn get_cached_ram_pct(&self) -> f32 {
        self.cached_ram_pct.load(Ordering::Relaxed) as f32 / 100.0
    }

    /// Get cached CPU percentage (no system call)
    pub fn get_cached_cpu_pct(&self) -> f32 {
        self.cached_cpu_pct.load(Ordering::Relaxed) as f32 / 100.0
    }

    /// Get available RAM in MB
    pub fn get_available_ram_mb(&self) -> u64 {
        let mut system = self.system.lock();
        system.refresh_memory();
        system.available_memory() / (1024 * 1024)
    }

    /// Get total RAM in MB
    pub fn get_total_ram_mb(&self) -> u64 {
        let system = self.system.lock();
        system.total_memory() / (1024 * 1024)
    }

    /// Get number of CPU cores
    pub fn get_cpu_count(&self) -> usize {
        let system = self.system.lock();
        system.cpus().len()
    }

    /// Check if RAM is critically low
    pub fn is_ram_critical(&self, threshold_pct: f32) -> bool {
        let (ram_pct, _, _) = self.get_ram_stats();
        ram_pct >= threshold_pct
    }

    /// Get memory info string for logging
    pub fn get_info_string(&self) -> String {
        let (ram_pct, used_mb, total_mb) = self.get_ram_stats();
        let cpu_pct = self.get_cpu_pct();
        format!(
            "RAM: {:.1}% ({}/{} MB) | CPU: {:.1}% ({} cores)",
            ram_pct, used_mb, total_mb,
            cpu_pct, self.get_cpu_count()
        )
    }
}

impl Default for RamMonitor {
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

    #[test]
    fn test_ram_monitor_creates() {
        let monitor = RamMonitor::new();
        let (pct, used, total) = monitor.get_ram_stats();
        assert!(pct >= 0.0 && pct <= 100.0);
        assert!(total > 0);
        assert!(used <= total);
    }

    #[test]
    fn test_cpu_pct_in_range() {
        let monitor = RamMonitor::new();
        let cpu = monitor.get_cpu_pct();
        assert!(cpu >= 0.0 && cpu <= 100.0);
    }

    #[test]
    fn test_total_ram_positive() {
        let monitor = RamMonitor::new();
        assert!(monitor.get_total_ram_mb() > 0);
    }

    #[test]
    fn test_cpu_count_positive() {
        let monitor = RamMonitor::new();
        assert!(monitor.get_cpu_count() > 0);
    }

    #[test]
    fn test_cached_values() {
        let monitor = RamMonitor::new();
        monitor.get_ram_stats(); // Populate cache
        let cached = monitor.get_cached_ram_pct();
        assert!(cached >= 0.0 && cached <= 100.0);
    }

    #[test]
    fn test_info_string_not_empty() {
        let monitor = RamMonitor::new();
        let info = monitor.get_info_string();
        assert!(!info.is_empty());
        assert!(info.contains("RAM"));
        assert!(info.contains("CPU"));
    }
}
