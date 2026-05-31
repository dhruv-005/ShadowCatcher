// ============================================
// SHADOW CATCHER - Connection Pool
// Manages reusable HTTP connections
// ============================================

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use parking_lot::Mutex;
use tracing::{info, debug, warn};

// ─────────────────────────────────────────
// CONNECTION ENTRY
// ─────────────────────────────────────────

/// A pooled connection entry
#[derive(Debug)]
struct ConnectionEntry {
    /// Host this connection is for
    host: String,
    /// When this connection was last used
    last_used: Instant,
    /// Number of requests served
    requests_served: u64,
    /// Whether connection is currently in use
    in_use: bool,
}

impl ConnectionEntry {
    fn new(host: String) -> Self {
        Self {
            host,
            last_used: Instant::now(),
            requests_served: 0,
            in_use: false,
        }
    }

    fn is_idle_too_long(&self, max_idle: Duration) -> bool {
        !self.in_use && self.last_used.elapsed() > max_idle
    }

    fn mark_used(&mut self) {
        self.last_used = Instant::now();
        self.in_use = true;
        self.requests_served += 1;
    }

    fn mark_free(&mut self) {
        self.last_used = Instant::now();
        self.in_use = false;
    }
}

// ─────────────────────────────────────────
// POOL STATS
// ─────────────────────────────────────────

/// Connection pool statistics
#[derive(Debug, Default, Clone)]
pub struct PoolStats {
    pub total_connections: usize,
    pub active_connections: usize,
    pub idle_connections: usize,
    pub total_requests: u64,
    pub cache_hits: u64,
    pub cache_misses: u64,
}

impl PoolStats {
    pub fn hit_rate(&self) -> f32 {
        let total = self.cache_hits + self.cache_misses;
        if total == 0 {
            return 0.0;
        }
        self.cache_hits as f32 / total as f32 * 100.0
    }
}

// ─────────────────────────────────────────
// CONNECTION POOL
// ─────────────────────────────────────────

/// Manages a pool of HTTP connections per host
pub struct ConnectionPool {
    /// Maximum connections per host
    max_per_host: usize,
    /// Maximum total connections
    max_total: usize,
    /// Maximum idle time before cleanup
    max_idle_duration: Duration,
    /// Pool state
    connections: Mutex<HashMap<String, Vec<ConnectionEntry>>>,
    /// Pool statistics
    stats: Mutex<PoolStats>,
}

impl ConnectionPool {
    /// Create a new connection pool
    pub fn new(max_concurrent: usize) -> Self {
        Self {
            max_per_host:      max_concurrent.max(2),
            max_total:         max_concurrent * 4,
            max_idle_duration: Duration::from_secs(90),
            connections:       Mutex::new(HashMap::new()),
            stats:             Mutex::new(PoolStats::default()),
        }
    }

    /// Create with custom settings
    pub fn with_settings(
        max_per_host: usize,
        max_total: usize,
        max_idle_secs: u64,
    ) -> Self {
        Self {
            max_per_host,
            max_total,
            max_idle_duration: Duration::from_secs(max_idle_secs),
            connections: Mutex::new(HashMap::new()),
            stats: Mutex::new(PoolStats::default()),
        }
    }

    // ─────────────────────────────────────
    // PUBLIC API
    // ─────────────────────────────────────

    /// Acquire a connection for the given host
    ///
    /// Returns connection ID if available,
    /// or None if pool is full.
    pub fn acquire(&self, host: &str) -> Option<usize> {
        let mut connections = self.connections.lock();
        let mut stats = self.stats.lock();

        // Check if we have an idle connection for this host
        if let Some(entries) = connections.get_mut(host) {
            for (idx, entry) in entries.iter_mut().enumerate() {
                if !entry.in_use {
                    entry.mark_used();
                    stats.active_connections += 1;
                    stats.cache_hits += 1;
                    stats.total_requests += 1;
                    debug!("Reusing connection for {}", host);
                    return Some(idx);
                }
            }
        }

        // Check total connection limit
        let total: usize = connections.values()
            .map(|v| v.len())
            .sum();

        if total >= self.max_total {
            warn!("Connection pool full ({} connections)", total);
            stats.cache_misses += 1;
            return None;
        }

        // Check per-host limit
        let host_count = connections
            .get(host)
            .map(|v| v.len())
            .unwrap_or(0);

        if host_count >= self.max_per_host {
            debug!("Per-host limit reached for {}", host);
            stats.cache_misses += 1;
            return None;
        }

        // Create new connection entry
        let mut entry = ConnectionEntry::new(host.to_string());
        entry.mark_used();

        let entries = connections
            .entry(host.to_string())
            .or_insert_with(Vec::new);
        entries.push(entry);

        let idx = entries.len() - 1;

        stats.total_connections += 1;
        stats.active_connections += 1;
        stats.cache_misses += 1;
        stats.total_requests += 1;

        debug!(
            "New connection for {} (total: {})",
            host,
            total + 1
        );

        Some(idx)
    }

    /// Release a connection back to the pool
    pub fn release(&self, host: &str, connection_id: usize) {
        let mut connections = self.connections.lock();
        let mut stats = self.stats.lock();

        if let Some(entries) = connections.get_mut(host) {
            if let Some(entry) = entries.get_mut(connection_id) {
                entry.mark_free();
                if stats.active_connections > 0 {
                    stats.active_connections -= 1;
                }
                debug!("Released connection for {}", host);
            }
        }
    }

    /// Clean up idle connections
    pub fn cleanup_idle(&self) -> usize {
        let mut connections = self.connections.lock();
        let mut stats = self.stats.lock();
        let mut removed = 0;

        for entries in connections.values_mut() {
            let before = entries.len();
            entries.retain(|e| !e.is_idle_too_long(self.max_idle_duration));
            let after = entries.len();
            removed += before - after;
        }

        // Remove empty host entries
        connections.retain(|_, v| !v.is_empty());

        if removed > 0 {
            info!("Cleaned up {} idle connections", removed);
            stats.total_connections =
                stats.total_connections.saturating_sub(removed);
            stats.idle_connections =
                stats.idle_connections.saturating_sub(removed);
        }

        removed
    }

    /// Get pool statistics
    pub fn get_stats(&self) -> PoolStats {
        let connections = self.connections.lock();
        let mut stats = self.stats.lock();

        let idle: usize = connections.values()
            .flat_map(|v| v.iter())
            .filter(|e| !e.in_use)
            .count();

        let active: usize = connections.values()
            .flat_map(|v| v.iter())
            .filter(|e| e.in_use)
            .count();

        stats.idle_connections = idle;
        stats.active_connections = active;
        stats.total_connections = idle + active;

        stats.clone()
    }

    /// Get number of connections for a specific host
    pub fn host_connection_count(&self, host: &str) -> usize {
        self.connections.lock()
            .get(host)
            .map(|v| v.len())
            .unwrap_or(0)
    }

    /// Get all tracked hosts
    pub fn get_hosts(&self) -> Vec<String> {
        self.connections.lock()
            .keys()
            .cloned()
            .collect()
    }

    /// Clear all connections for a host
    pub fn clear_host(&self, host: &str) {
        self.connections.lock().remove(host);
        debug!("Cleared all connections for {}", host);
    }

    /// Clear entire pool
    pub fn clear_all(&self) {
        self.connections.lock().clear();
        *self.stats.lock() = PoolStats::default();
        info!("Connection pool cleared");
    }

    /// Check if pool has available slot for host
    pub fn has_available_slot(&self, host: &str) -> bool {
        let connections = self.connections.lock();

        // Check for idle connection
        if let Some(entries) = connections.get(host) {
            if entries.iter().any(|e| !e.in_use) {
                return true;
            }
            // Check per-host limit
            if entries.len() >= self.max_per_host {
                return false;
            }
        }

        // Check total limit
        let total: usize = connections.values().map(|v| v.len()).sum();
        total < self.max_total
    }
}

// ─────────────────────────────────────────
// TESTS
// ─────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pool_creates() {
        let pool = ConnectionPool::new(4);
        let stats = pool.get_stats();
        assert_eq!(stats.total_connections, 0);
    }

    #[test]
    fn test_acquire_new_connection() {
        let pool = ConnectionPool::new(4);
        let conn = pool.acquire("example.com");
        assert!(conn.is_some());
    }

    #[test]
    fn test_acquire_reuses_idle() {
        let pool = ConnectionPool::new(4);

        // Acquire and release
        let conn1 = pool.acquire("example.com").unwrap();
        pool.release("example.com", conn1);

        // Should reuse
        let stats_before = pool.get_stats();
        let conn2 = pool.acquire("example.com");
        assert!(conn2.is_some());

        let stats_after = pool.get_stats();
        // Hits should increase
        assert!(stats_after.cache_hits >= stats_before.cache_hits);
    }

    #[test]
    fn test_per_host_limit() {
        let pool = ConnectionPool::with_settings(2, 10, 90);

        let _c1 = pool.acquire("example.com").unwrap();
        let _c2 = pool.acquire("example.com").unwrap();
        let c3  = pool.acquire("example.com");

        // Third should fail due to per-host limit
        assert!(c3.is_none());
    }

    #[test]
    fn test_different_hosts() {
        let pool = ConnectionPool::new(4);

        let c1 = pool.acquire("host1.com");
        let c2 = pool.acquire("host2.com");
        let c3 = pool.acquire("host3.com");

        assert!(c1.is_some());
        assert!(c2.is_some());
        assert!(c3.is_some());
    }

    #[test]
    fn test_clear_host() {
        let pool = ConnectionPool::new(4);
        pool.acquire("example.com");
        assert_eq!(pool.host_connection_count("example.com"), 1);

        pool.clear_host("example.com");
        assert_eq!(pool.host_connection_count("example.com"), 0);
    }

    #[test]
    fn test_clear_all() {
        let pool = ConnectionPool::new(4);
        pool.acquire("host1.com");
        pool.acquire("host2.com");

        pool.clear_all();
        assert_eq!(pool.get_hosts().len(), 0);
    }

    #[test]
    fn test_has_available_slot() {
        let pool = ConnectionPool::with_settings(1, 10, 90);
        assert!(pool.has_available_slot("example.com"));

        pool.acquire("example.com");
        // Per-host limit reached
        assert!(!pool.has_available_slot("example.com"));
    }

    #[test]
    fn test_pool_stats_hit_rate() {
        let stats = PoolStats {
            cache_hits: 8,
            cache_misses: 2,
            ..Default::default()
        };
        assert!((stats.hit_rate() - 80.0).abs() < 0.01);
    }

    #[test]
    fn test_cleanup_idle() {
        let pool = ConnectionPool::with_settings(4, 10, 0);
        pool.acquire("example.com");
        pool.release("example.com", 0);

        // With 0 second idle timeout, should clean up immediately
        std::thread::sleep(Duration::from_millis(10));
        let removed = pool.cleanup_idle();
        assert!(removed > 0);
    }
}
