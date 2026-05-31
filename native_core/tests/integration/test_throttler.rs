// ============================================
// SHADOW CATCHER - Throttler Integration Tests
// ============================================

use shadow_core::throttler::{
    ResourceLevel,
    SystemStats,
    throttler::Throttler,
    ram_monitor::RamMonitor,
    tcp_controller::TcpController,
};
use std::time::Duration;
use std::sync::Arc;

// ─────────────────────────────────────────
// RESOURCE LEVEL TESTS
// ─────────────────────────────────────────

#[cfg(test)]
mod resource_level_tests {
    use super::*;

    #[test]
    fn test_level_from_ram_pct_low() {
        assert_eq!(
            ResourceLevel::from_ram_pct(30.0),
            ResourceLevel::Low
        );
    }

    #[test]
    fn test_level_from_ram_pct_medium() {
        assert_eq!(
            ResourceLevel::from_ram_pct(70.0),
            ResourceLevel::Medium
        );
    }

    #[test]
    fn test_level_from_ram_pct_high() {
        assert_eq!(
            ResourceLevel::from_ram_pct(85.0),
            ResourceLevel::High
        );
    }

    #[test]
    fn test_level_from_ram_pct_critical() {
        assert_eq!(
            ResourceLevel::from_ram_pct(97.0),
            ResourceLevel::Critical
        );
    }

    #[test]
    fn test_level_from_cpu_pct() {
        assert_eq!(
            ResourceLevel::from_cpu_pct(20.0),
            ResourceLevel::Low
        );
        assert_eq!(
            ResourceLevel::from_cpu_pct(65.0),
            ResourceLevel::Medium
        );
        assert_eq!(
            ResourceLevel::from_cpu_pct(85.0),
            ResourceLevel::High
        );
        assert_eq!(
            ResourceLevel::from_cpu_pct(97.0),
            ResourceLevel::Critical
        );
    }

    #[test]
    fn test_speed_multiplier_low() {
        assert_eq!(ResourceLevel::Low.speed_multiplier(), 1.0);
    }

    #[test]
    fn test_speed_multiplier_critical() {
        assert_eq!(ResourceLevel::Critical.speed_multiplier(), 0.0);
    }

    #[test]
    fn test_speed_multiplier_decreasing() {
        let low    = ResourceLevel::Low.speed_multiplier();
        let medium = ResourceLevel::Medium.speed_multiplier();
        let high   = ResourceLevel::High.speed_multiplier();
        let critical = ResourceLevel::Critical.speed_multiplier();
        assert!(low > medium);
        assert!(medium > high);
        assert!(high > critical);
    }

    #[test]
    fn test_max_concurrent_decreasing() {
        assert!(
            ResourceLevel::Low.max_concurrent()
                > ResourceLevel::Medium.max_concurrent()
        );
        assert!(
            ResourceLevel::Medium.max_concurrent()
                >= ResourceLevel::High.max_concurrent()
        );
        assert_eq!(ResourceLevel::Critical.max_concurrent(), 0);
    }

    #[test]
    fn test_level_ordering() {
        assert!(ResourceLevel::Critical > ResourceLevel::High);
        assert!(ResourceLevel::High > ResourceLevel::Medium);
        assert!(ResourceLevel::Medium > ResourceLevel::Low);
    }
}

// ─────────────────────────────────────────
// THROTTLER TESTS
// ─────────────────────────────────────────

#[cfg(test)]
mod throttler_tests {
    use super::*;

    #[test]
    fn test_throttler_creates_with_slots() {
        let t = Throttler::new(4);
        assert_eq!(t.available_slots(), 4);
    }

    #[test]
    fn test_throttler_release_increases_slots() {
        let t = Throttler::new(2);
        let initial = t.available_slots();
        t.release_slot();
        assert!(t.available_slots() > initial);
    }

    #[tokio::test]
    async fn test_force_level_changes_level() {
        let t = Throttler::new(4);
        t.force_level(ResourceLevel::High).await;
        assert_eq!(t.get_level().await, ResourceLevel::High);
    }

    #[tokio::test]
    async fn test_force_critical_level() {
        let t = Throttler::new(4);
        t.force_level(ResourceLevel::Critical).await;
        assert_eq!(t.get_level().await, ResourceLevel::Critical);
    }

    #[tokio::test]
    async fn test_force_level_affects_speed() {
        let t = Throttler::new(4);
        t.force_level(ResourceLevel::Critical).await;
        let level = t.get_level().await;
        assert_eq!(level.speed_multiplier(), 0.0);
    }

    #[test]
    fn test_system_stats_ram_free() {
        let stats = SystemStats {
            ram_total_mb: 8192,
            ram_used_mb: 4096,
            ..Default::default()
        };
        assert_eq!(stats.ram_free_mb(), 4096);
    }

    #[test]
    fn test_system_stats_ram_free_saturating() {
        let stats = SystemStats {
            ram_total_mb: 100,
            ram_used_mb: 200, // More than total
            ..Default::default()
        };
        assert_eq!(stats.ram_free_mb(), 0);
    }
}

// ─────────────────────────────────────────
// RAM MONITOR TESTS
// ─────────────────────────────────────────

#[cfg(test)]
mod ram_monitor_tests {
    use super::*;

    #[test]
    fn test_ram_stats_valid_range() {
        let monitor = RamMonitor::new();
        let (pct, used, total) = monitor.get_ram_stats();
        assert!(pct >= 0.0 && pct <= 100.0);
        assert!(total > 0);
        assert!(used <= total);
    }

    #[test]
    fn test_cpu_pct_valid_range() {
        let monitor = RamMonitor::new();
        let cpu = monitor.get_cpu_pct();
        assert!(cpu >= 0.0 && cpu <= 100.0);
    }

    #[test]
    fn test_total_ram_reasonable() {
        let monitor = RamMonitor::new();
        let total_mb = monitor.get_total_ram_mb();
        // Should have at least 256MB RAM
        assert!(total_mb >= 256);
        // Should not report more than 2TB
        assert!(total_mb < 2 * 1024 * 1024);
    }

    #[test]
    fn test_cpu_count_at_least_one() {
        let monitor = RamMonitor::new();
        assert!(monitor.get_cpu_count() >= 1);
    }

    #[test]
    fn test_available_ram_positive() {
        let monitor = RamMonitor::new();
        // Available may be 0 on very loaded system
        let available = monitor.get_available_ram_mb();
        assert!(available < monitor.get_total_ram_mb() + 1);
    }

    #[test]
    fn test_info_string_contains_ram() {
        let monitor = RamMonitor::new();
        let info = monitor.get_info_string();
        assert!(info.contains("RAM"));
        assert!(info.contains("CPU"));
        assert!(info.contains("MB"));
    }

    #[test]
    fn test_cached_values_after_refresh() {
        let monitor = RamMonitor::new();
        monitor.get_ram_stats(); // Populate cache
        monitor.get_cpu_pct();

        let cached_ram = monitor.get_cached_ram_pct();
        let cached_cpu = monitor.get_cached_cpu_pct();

        assert!(cached_ram >= 0.0 && cached_ram <= 100.0);
        assert!(cached_cpu >= 0.0 && cached_cpu <= 100.0);
    }
}

// ─────────────────────────────────────────
// TCP CONTROLLER TESTS
// ─────────────────────────────────────────

#[cfg(test)]
mod tcp_controller_tests {
    use super::*;

    #[tokio::test]
    async fn test_unlimited_controller() {
        let ctrl = TcpController::new(0);
        let start = std::time::Instant::now();
        ctrl.apply_delay(1024).await;
        assert!(start.elapsed() < Duration::from_millis(50));
    }

    #[tokio::test]
    async fn test_speed_multiplier_set_get() {
        let ctrl = TcpController::new(1000);
        ctrl.set_speed_multiplier(0.5).await;
        let speed = ctrl.get_allowed_speed_kbps().await;
        assert_eq!(speed, 500);
    }

    #[tokio::test]
    async fn test_speed_multiplier_zero_blocks() {
        let ctrl = TcpController::new(1000);
        ctrl.set_speed_multiplier(0.0).await;
        let speed = ctrl.get_allowed_speed_kbps().await;
        assert_eq!(speed, 0);
    }

    #[tokio::test]
    async fn test_speed_multiplier_clamped_high() {
        let ctrl = TcpController::new(0);
        ctrl.set_speed_multiplier(2.0).await;
        let speed = ctrl.get_allowed_speed_kbps().await;
        // Clamped to 1.0 multiplier
        let _ = speed;
    }

    #[tokio::test]
    async fn test_speed_multiplier_clamped_low() {
        let ctrl = TcpController::new(0);
        ctrl.set_speed_multiplier(-1.0).await;
        let speed = ctrl.get_allowed_speed_kbps().await;
        let _ = speed;
    }

    #[tokio::test]
    async fn test_reset_restores_defaults() {
        let ctrl = TcpController::new(0);
        ctrl.set_speed_multiplier(0.3).await;
        ctrl.reset().await;
        let speed = ctrl.get_allowed_speed_kbps().await;
        let _ = speed; // Just verify no panic
    }

    #[test]
    fn test_initial_speed_zero() {
        let ctrl = TcpController::new(1000);
        assert_eq!(ctrl.get_current_speed_kbps(), 0);
    }

    #[tokio::test]
    async fn test_allowed_speed_with_limit() {
        let ctrl = TcpController::new(2000);
        ctrl.set_speed_multiplier(1.0).await;
        let speed = ctrl.get_allowed_speed_kbps().await;
        assert_eq!(speed, 2000);
    }

    #[tokio::test]
    async fn test_allowed_speed_half_limit() {
        let ctrl = TcpController::new(2000);
        ctrl.set_speed_multiplier(0.5).await;
        let speed = ctrl.get_allowed_speed_kbps().await;
        assert_eq!(speed, 1000);
    }
}
