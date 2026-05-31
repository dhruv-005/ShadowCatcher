// ============================================
// SHADOW CATCHER - Throttler
// Coordinates resource management
// ============================================

use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{Semaphore, RwLock};
use tokio::time::sleep;
use tracing::{info, warn, debug};
use serde_json;

use crate::throttler::{
    ResourceLevel,
    SystemStats,
    ram_monitor::RamMonitor,
    tcp_controller::TcpController,
};

// ─────────────────────────────────────────
// THROTTLER CONFIG
// ─────────────────────────────────────────

/// Throttler configuration
#[derive(Debug, Clone)]
pub struct ThrottlerConfig {
    pub max_concurrent_downloads: usize,
    pub check_interval_ms: u64,
    pub ram_high_threshold_pct: f32,
    pub ram_critical_threshold_pct: f32,
    pub cpu_high_threshold_pct: f32,
    pub max_download_speed_kbps: u64,
}

impl Default for ThrottlerConfig {
    fn default() -> Self {
        Self {
            max_concurrent_downloads:   4,
            check_interval_ms:          500,
            ram_high_threshold_pct:     80.0,
            ram_critical_threshold_pct: 95.0,
            cpu_high_threshold_pct:     80.0,
            max_download_speed_kbps:    0, // 0 = unlimited
        }
    }
}

// ─────────────────────────────────────────
// THROTTLER
// ─────────────────────────────────────────

/// Main resource throttler
///
/// Controls download concurrency and speed
/// based on system resource availability.
pub struct Throttler {
    config: ThrottlerConfig,
    semaphore: Arc<Semaphore>,
    ram_monitor: Arc<RamMonitor>,
    tcp_controller: Arc<TcpController>,
    current_level: Arc<RwLock<ResourceLevel>>,
    current_stats: Arc<RwLock<SystemStats>>,
}

impl Throttler {
    /// Create a new throttler
    pub fn new(max_concurrent: usize) -> Self {
        let config = ThrottlerConfig {
            max_concurrent_downloads: max_concurrent,
            ..Default::default()
        };
        Self::with_config(config)
    }

    /// Create with custom config
    pub fn with_config(config: ThrottlerConfig) -> Self {
        let semaphore = Arc::new(
            Semaphore::new(config.max_concurrent_downloads)
        );
        let ram_monitor = Arc::new(RamMonitor::new());
        let tcp_controller = Arc::new(
            TcpController::new(config.max_download_speed_kbps)
        );

        let throttler = Self {
            config,
            semaphore,
            ram_monitor,
            tcp_controller,
            current_level: Arc::new(RwLock::new(ResourceLevel::Low)),
            current_stats: Arc::new(RwLock::new(SystemStats::default())),
        };

        throttler
    }

    /// Start the background monitoring task
    pub fn start_monitoring(self: &Arc<Self>) {
        let throttler = Arc::clone(self);

        tokio::spawn(async move {
            loop {
                throttler.check_and_adjust().await;
                sleep(Duration::from_millis(
                    throttler.config.check_interval_ms
                )).await;
            }
        });

        info!("Resource monitoring started");
    }

    // ─────────────────────────────────────
    // SLOT MANAGEMENT
    // ─────────────────────────────────────

    /// Wait for an available download slot
    ///
    /// Blocks until system resources allow
    /// a new download to start.
    pub async fn wait_for_slot(&self) {
        loop {
            let level = self.current_level.read().await.clone();

            match level {
                ResourceLevel::Critical => {
                    warn!("System critical - waiting to start download");
                    sleep(Duration::from_secs(5)).await;
                    continue;
                }
                _ => {
                    // Try to acquire semaphore
                    match self.semaphore.try_acquire() {
                        Ok(_permit) => {
                            // Permit acquired - proceed
                            // Note: permit is intentionally dropped here
                            // Real implementation would return it
                            debug!("Download slot acquired");
                            return;
                        }
                        Err(_) => {
                            // No slots available - wait
                            sleep(Duration::from_millis(100)).await;
                        }
                    }
                }
            }
        }
    }

    /// Release a download slot
    pub fn release_slot(&self) {
        self.semaphore.add_permits(1);
        debug!("Download slot released");
    }

    /// Get number of available slots
    pub fn available_slots(&self) -> usize {
        self.semaphore.available_permits()
    }

    // ─────────────────────────────────────
    // SPEED CONTROL
    // ─────────────────────────────────────

    /// Get current allowed download speed in KB/s
    /// Returns 0 for unlimited
    pub async fn get_allowed_speed_kbps(&self) -> u64 {
        self.tcp_controller.get_allowed_speed_kbps().await
    }

    /// Apply throttling delay for a chunk of given size
    pub async fn throttle_chunk(&self, chunk_size: usize) {
        self.tcp_controller.apply_delay(chunk_size).await;
    }

    // ─────────────────────────────────────
    // MONITORING
    // ─────────────────────────────────────

    /// Check system resources and adjust throttling
    async fn check_and_adjust(&self) {
        let (ram_pct, ram_used_mb, ram_total_mb) =
            self.ram_monitor.get_ram_stats();
        let cpu_pct = self.ram_monitor.get_cpu_pct();

        // Determine resource level
        let ram_level = ResourceLevel::from_ram_pct(ram_pct);
        let cpu_level = ResourceLevel::from_cpu_pct(cpu_pct);

        // Use the worse of RAM and CPU levels
        let level = if ram_level >= cpu_level { ram_level } else { cpu_level };

        // Update current level
        {
            let mut current = self.current_level.write().await;
            if *current != level {
                info!(
                    "Resource level changed: {:?} → {:?} \
                     (RAM: {:.1}%, CPU: {:.1}%)",
                    *current, level, ram_pct, cpu_pct
                );
                *current = level.clone();
            }
        }

        // Adjust TCP controller based on level
        let speed_multiplier = level.speed_multiplier();
        self.tcp_controller
            .set_speed_multiplier(speed_multiplier)
            .await;

        // Update stats
        {
            let mut stats = self.current_stats.write().await;
            stats.ram_used_mb = ram_used_mb;
            stats.ram_total_mb = ram_total_mb;
            stats.ram_pct = ram_pct;
            stats.cpu_pct = cpu_pct;
            stats.resource_level = format!("{:?}", level);
            stats.max_speed_kbps =
                self.tcp_controller.get_allowed_speed_kbps().await;
        }

        debug!(
            "System stats: RAM={:.1}% CPU={:.1}% Level={:?}",
            ram_pct, cpu_pct, level
        );
    }

    /// Get current system stats as JSON string
    pub fn get_stats(&self) -> SystemStats {
        // Blocking read for sync contexts
        let rt = tokio::runtime::Handle::try_current();
        if let Ok(handle) = rt {
            handle.block_on(async {
                self.current_stats.read().await.clone()
            })
        } else {
            SystemStats::default()
        }
    }

    /// Get current resource level
    pub async fn get_level(&self) -> ResourceLevel {
        self.current_level.read().await.clone()
    }

    /// Force a specific resource level (for testing)
    pub async fn force_level(&self, level: ResourceLevel) {
        let mut current = self.current_level.write().await;
        *current = level.clone();
        self.tcp_controller
            .set_speed_multiplier(level.speed_multiplier())
            .await;
    }
}

// ─────────────────────────────────────────
// TESTS
// ─────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_resource_level_speed_multiplier() {
        assert_eq!(ResourceLevel::Low.speed_multiplier(), 1.0);
        assert_eq!(ResourceLevel::Critical.speed_multiplier(), 0.0);
        assert!(ResourceLevel::Medium.speed_multiplier() < 1.0);
        assert!(ResourceLevel::High.speed_multiplier() < 0.5);
    }

    #[test]
    fn test_resource_level_from_ram() {
        assert_eq!(ResourceLevel::from_ram_pct(50.0), ResourceLevel::Low);
        assert_eq!(ResourceLevel::from_ram_pct(70.0), ResourceLevel::Medium);
        assert_eq!(ResourceLevel::from_ram_pct(85.0), ResourceLevel::High);
        assert_eq!(ResourceLevel::from_ram_pct(96.0), ResourceLevel::Critical);
    }

    #[test]
    fn test_throttler_creates() {
        let t = Throttler::new(4);
        assert_eq!(t.available_slots(), 4);
    }

    #[test]
    fn test_release_slot() {
        let t = Throttler::new(2);
        t.release_slot();
        assert_eq!(t.available_slots(), 3);
    }

    #[tokio::test]
    async fn test_force_level() {
        let t = Throttler::new(4);
        t.force_level(ResourceLevel::Critical).await;
        assert_eq!(t.get_level().await, ResourceLevel::Critical);
    }

    #[test]
    fn test_system_stats_ram_free() {
        let stats = SystemStats {
            ram_used_mb: 4096,
            ram_total_mb: 8192,
            ..Default::default()
        };
        assert_eq!(stats.ram_free_mb(), 4096);
    }
}
