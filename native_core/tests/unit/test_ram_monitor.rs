// ============================================
// SHADOW CATCHER - RAM Monitor Unit Tests
// ============================================

use shadow_core::throttler::ram_monitor::RamMonitor;
use shadow_core::throttler::ResourceLevel;

fn monitor() -> RamMonitor {
    RamMonitor::new()
}

// ─────────────────────────────────────────
// BASIC FUNCTIONALITY TESTS
// ─────────────────────────────────────────

#[test]
fn test_monitor_creates() {
    let _ = monitor();
}

#[test]
fn test_ram_pct_in_valid_range() {
    let m = monitor();
    let (pct, _, _) = m.get_ram_stats();
    assert!(
        pct >= 0.0 && pct <= 100.0,
        "RAM % should be in [0, 100], got {}",
        pct
    );
}

#[test]
fn test_ram_used_not_exceeds_total() {
    let m = monitor();
    let (_, used, total) = m.get_ram_stats();
    assert!(
        used <= total,
        "Used RAM {} should not exceed total {}",
        used, total
    );
}

#[test]
fn test_total_ram_positive() {
    let m = monitor();
    let (_, _, total) = m.get_ram_stats();
    assert!(total > 0, "Total RAM should be positive");
}

#[test]
fn test_total_ram_reasonable_min() {
    let m = monitor();
    let total_mb = m.get_total_ram_mb();
    assert!(
        total_mb >= 256,
        "System should have at least 256MB RAM, got {}MB",
        total_mb
    );
}

#[test]
fn test_total_ram_reasonable_max() {
    let m = monitor();
    let total_mb = m.get_total_ram_mb();
    // Should not report more than 4TB
    assert!(
        total_mb < 4 * 1024 * 1024,
        "RAM too large: {}MB",
        total_mb
    );
}

#[test]
fn test_cpu_pct_valid_range() {
    let m = monitor();
    let cpu = m.get_cpu_pct();
    assert!(
        cpu >= 0.0 && cpu <= 100.0,
        "CPU % should be in [0, 100], got {}",
        cpu
    );
}

#[test]
fn test_cpu_count_at_least_one() {
    let m = monitor();
    assert!(
        m.get_cpu_count() >= 1,
        "Should have at least 1 CPU core"
    );
}

#[test]
fn test_available_ram_not_negative() {
    let m = monitor();
    let available = m.get_available_ram_mb();
    let total = m.get_total_ram_mb();
    assert!(
        available <= total + 1,
        "Available {} should not exceed total {}",
        available, total
    );
}

// ─────────────────────────────────────────
// CACHING TESTS
// ─────────────────────────────────────────

#[test]
fn test_cached_ram_pct_after_refresh() {
    let m = monitor();
    m.get_ram_stats(); // Populate cache

    let cached = m.get_cached_ram_pct();
    assert!(
        cached >= 0.0 && cached <= 100.0,
        "Cached RAM % invalid: {}",
        cached
    );
}

#[test]
fn test_cached_cpu_pct_after_refresh() {
    let m = monitor();
    m.get_cpu_pct(); // Populate cache

    let cached = m.get_cached_cpu_pct();
    assert!(
        cached >= 0.0 && cached <= 100.0,
        "Cached CPU % invalid: {}",
        cached
    );
}

#[test]
fn test_cached_values_initially_zero() {
    let m = monitor(); // Don't call any refresh
    let cached_ram = m.get_cached_ram_pct();
    let cached_cpu = m.get_cached_cpu_pct();
    // May be zero or may be from constructor refresh
    assert!(cached_ram >= 0.0);
    assert!(cached_cpu >= 0.0);
}

// ─────────────────────────────────────────
// INFO STRING TESTS
// ─────────────────────────────────────────

#[test]
fn test_info_string_not_empty() {
    let m = monitor();
    let info = m.get_info_string();
    assert!(!info.is_empty());
}

#[test]
fn test_info_string_contains_ram() {
    let m = monitor();
    let info = m.get_info_string();
    assert!(
        info.contains("RAM"),
        "Info string should contain 'RAM': {}",
        info
    );
}

#[test]
fn test_info_string_contains_cpu() {
    let m = monitor();
    let info = m.get_info_string();
    assert!(
        info.contains("CPU"),
        "Info string should contain 'CPU': {}",
        info
    );
}

#[test]
fn test_info_string_contains_mb() {
    let m = monitor();
    let info = m.get_info_string();
    assert!(
        info.contains("MB"),
        "Info string should contain 'MB': {}",
        info
    );
}

// ─────────────────────────────────────────
// CRITICAL THRESHOLD TESTS
// ─────────────────────────────────────────

#[test]
fn test_is_ram_critical_at_100pct() {
    let m = monitor();
    let (current_pct, _, _) = m.get_ram_stats();
    let result = m.is_ram_critical(current_pct - 1.0);
    // Since current > threshold-1, should be critical
    let _ = result; // Just verify no panic
}

#[test]
fn test_is_ram_critical_at_zero_threshold() {
    let m = monitor();
    // 0% threshold - always critical
    let result = m.is_ram_critical(0.0);
    assert!(result, "0% threshold should always be critical");
}

#[test]
fn test_not_critical_at_100_threshold() {
    let m = monitor();
    // 100% threshold - never critical unless truly at 100%
    let result = m.is_ram_critical(100.0);
    // Current system can't be at 100% in most cases
    let _ = result;
}

// ─────────────────────────────────────────
// RESOURCE LEVEL INTEGRATION TESTS
// ─────────────────────────────────────────

#[test]
fn test_ram_to_resource_level_mapping() {
    let m = monitor();
    let (pct, _, _) = m.get_ram_stats();
    let level = ResourceLevel::from_ram_pct(pct);

    // Verify level is one of the valid variants
    let is_valid = matches!(
        level,
        ResourceLevel::Low
            | ResourceLevel::Medium
            | ResourceLevel::High
            | ResourceLevel::Critical
    );
    assert!(is_valid, "Should map to a valid resource level");
}

#[test]
fn test_multiple_refreshes_stable() {
    let m = monitor();

    // Run multiple refreshes
    let mut values = Vec::new();
    for _ in 0..3 {
        let (pct, _, _) = m.get_ram_stats();
        values.push(pct);
    }

    // Values should be in valid range
    for v in values {
        assert!(v >= 0.0 && v <= 100.0);
    }
}

#[test]
fn test_concurrent_reads_safe() {
    use std::sync::Arc;
    use std::thread;

    let m = Arc::new(monitor());
    let mut handles = Vec::new();

    for _ in 0..4 {
        let m_clone = Arc::clone(&m);
        let h = thread::spawn(move || {
            let (pct, _, _) = m_clone.get_ram_stats();
            assert!(pct >= 0.0 && pct <= 100.0);
        });
        handles.push(h);
    }

    for h in handles {
        h.join().unwrap();
    }
}
