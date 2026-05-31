// ============================================
// SHADOW CATCHER - TCP Controller
// Controls download speed via rate limiting
// ============================================

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use tokio::time::sleep;
use tracing::debug;

// ─────────────────────────────────────────
// TCP CONTROLLER
// ─────────────────────────────────────────

/// Controls download speed via token bucket rate limiting
pub struct TcpController {
    /// Maximum speed in KB/s (0 = unlimited)
    max_speed_kbps: u64,
    /// Current speed multiplier [0.0, 1.0]
    speed_multiplier: Arc<RwLock<f32>>,
    /// Token bucket: available bytes to send
    available_tokens: Arc<AtomicU64>,
    /// Last token refill time
    last_refill: Arc<RwLock<Instant>>,
    /// Current measured speed in KB/s
    current_speed_kbps: Arc<AtomicU64>,
    /// Bytes sent in current measurement window
    bytes_in_window: Arc<AtomicU64>,
    /// Window start time
    window_start: Arc<RwLock<Instant>>,
}

impl TcpController {
    /// Create a new TCP controller
    ///
    /// # Arguments
    /// * `max_speed_kbps` - Maximum speed in KB/s. 0 = unlimited.
    pub fn new(max_speed_kbps: u64) -> Self {
        let initial_tokens = if max_speed_kbps > 0 {
            max_speed_kbps * 1024 // Convert to bytes
        } else {
            u64::MAX / 2 // Effectively unlimited
        };

        Self {
            max_speed_kbps,
            speed_multiplier: Arc::new(RwLock::new(1.0)),
            available_tokens: Arc::new(AtomicU64::new(initial_tokens)),
            last_refill: Arc::new(RwLock::new(Instant::now())),
            current_speed_kbps: Arc::new(AtomicU64::new(0)),
            bytes_in_window: Arc::new(AtomicU64::new(0)),
            window_start: Arc::new(RwLock::new(Instant::now())),
        }
    }

    // ─────────────────────────────────────
    // PUBLIC API
    // ─────────────────────────────────────

    /// Apply rate limiting delay for a chunk
    ///
    /// Call this after writing each chunk to
    /// enforce speed limits.
    pub async fn apply_delay(&self, chunk_size: usize) {
        // Update speed measurement
        self.update_speed_measurement(chunk_size).await;

        let multiplier = *self.speed_multiplier.read().await;

        // If unlimited and no throttling needed, return immediately
        if self.max_speed_kbps == 0 && multiplier >= 1.0 {
            return;
        }

        // Refill tokens based on elapsed time
        self.refill_tokens().await;

        let chunk_bytes = chunk_size as u64;

        // Check if we have enough tokens
        loop {
            let available = self.available_tokens.load(Ordering::Relaxed);

            if available >= chunk_bytes {
                // Consume tokens
                self.available_tokens.fetch_sub(chunk_bytes, Ordering::Relaxed);
                break;
            } else {
                // Wait for token refill
                sleep(Duration::from_millis(10)).await;
                self.refill_tokens().await;
            }
        }

        // Apply additional delay based on speed multiplier
        if multiplier < 1.0 {
            let base_delay = self.calculate_delay(chunk_size).await;
            let adjusted_delay = if multiplier <= 0.0 {
                Duration::from_secs(60) // Pause
            } else {
                Duration::from_micros(
                    (base_delay.as_micros() as f32 / multiplier) as u64
                )
            };

            if adjusted_delay > Duration::from_millis(1) {
                sleep(adjusted_delay).await;
            }
        }
    }

    /// Set speed multiplier [0.0, 1.0]
    pub async fn set_speed_multiplier(&self, multiplier: f32) {
        let clamped = multiplier.clamp(0.0, 1.0);
        let mut m = self.speed_multiplier.write().await;
        if (*m - clamped).abs() > 0.01 {
            debug!("Speed multiplier: {:.2} → {:.2}", *m, clamped);
        }
        *m = clamped;
    }

    /// Get current allowed speed in KB/s
    pub async fn get_allowed_speed_kbps(&self) -> u64 {
        let multiplier = *self.speed_multiplier.read().await;

        if self.max_speed_kbps == 0 {
            // Unlimited - return measured speed * multiplier
            let measured = self.current_speed_kbps.load(Ordering::Relaxed);
            return (measured as f32 * multiplier) as u64;
        }

        (self.max_speed_kbps as f32 * multiplier) as u64
    }

    /// Get current measured download speed in KB/s
    pub fn get_current_speed_kbps(&self) -> u64 {
        self.current_speed_kbps.load(Ordering::Relaxed)
    }

    /// Set maximum speed limit
    pub fn set_max_speed_kbps(&mut self, max_kbps: u64) {
        self.max_speed_kbps = max_kbps;
        let tokens = if max_kbps > 0 {
            max_kbps * 1024
        } else {
            u64::MAX / 2
        };
        self.available_tokens.store(tokens, Ordering::Relaxed);
    }

    /// Reset the controller state
    pub async fn reset(&self) {
        let mut multiplier = self.speed_multiplier.write().await;
        *multiplier = 1.0;
        self.current_speed_kbps.store(0, Ordering::Relaxed);
        self.bytes_in_window.store(0, Ordering::Relaxed);

        let mut window = self.window_start.write().await;
        *window = Instant::now();
    }

    // ─────────────────────────────────────
    // INTERNAL
    // ─────────────────────────────────────

    /// Refill token bucket based on elapsed time
    async fn refill_tokens(&self) {
        if self.max_speed_kbps == 0 {
            return; // Unlimited - no refill needed
        }

        let mut last_refill = self.last_refill.write().await;
        let elapsed = last_refill.elapsed();
        let elapsed_secs = elapsed.as_secs_f64();

        if elapsed_secs > 0.001 {
            // Calculate tokens to add
            let multiplier = *self.speed_multiplier.read().await;
            let effective_speed = self.max_speed_kbps as f64 * multiplier as f64;
            let tokens_to_add = (effective_speed * 1024.0 * elapsed_secs) as u64;

            let max_tokens = self.max_speed_kbps * 1024 * 2; // 2-second burst
            let current = self.available_tokens.load(Ordering::Relaxed);
            let new_tokens = (current + tokens_to_add).min(max_tokens);

            self.available_tokens.store(new_tokens, Ordering::Relaxed);
            *last_refill = Instant::now();
        }
    }

    /// Calculate delay for a chunk to maintain speed limit
    async fn calculate_delay(&self, chunk_size: usize) -> Duration {
        if self.max_speed_kbps == 0 {
            return Duration::ZERO;
        }

        let multiplier = *self.speed_multiplier.read().await;
        let effective_kbps = self.max_speed_kbps as f64 * multiplier as f64;

        if effective_kbps <= 0.0 {
            return Duration::from_secs(1);
        }

        let bytes_per_sec = effective_kbps * 1024.0;
        let secs_needed = chunk_size as f64 / bytes_per_sec;
        Duration::from_secs_f64(secs_needed)
    }

    /// Update speed measurement
    async fn update_speed_measurement(&self, chunk_size: usize) {
        self.bytes_in_window.fetch_add(chunk_size as u64, Ordering::Relaxed);

        let window_elapsed = {
            let window_start = self.window_start.read().await;
            window_start.elapsed()
        };

        // Update speed every 500ms
        if window_elapsed >= Duration::from_millis(500) {
            let bytes = self.bytes_in_window.swap(0, Ordering::Relaxed);
            let elapsed_secs = window_elapsed.as_secs_f64();
            let speed_kbps = (bytes as f64 / elapsed_secs / 1024.0) as u64;

            self.current_speed_kbps.store(speed_kbps, Ordering::Relaxed);

            let mut window_start = self.window_start.write().await;
            *window_start = Instant::now();

            debug!("Download speed: {} KB/s", speed_kbps);
        }
    }
}

// ─────────────────────────────────────────
// TESTS
// ─────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_unlimited_no_delay() {
        let ctrl = TcpController::new(0);
        let start = Instant::now();
        ctrl.apply_delay(1024 * 1024).await; // 1MB chunk
        let elapsed = start.elapsed();
        assert!(elapsed < Duration::from_millis(50));
    }

    #[tokio::test]
    async fn test_speed_multiplier_set() {
        let ctrl = TcpController::new(0);
        ctrl.set_speed_multiplier(0.5).await;
        let m = *ctrl.speed_multiplier.read().await;
        assert!((m - 0.5).abs() < 0.01);
    }

    #[tokio::test]
    async fn test_speed_multiplier_clamped() {
        let ctrl = TcpController::new(0);
        ctrl.set_speed_multiplier(1.5).await; // Over 1.0
        let m = *ctrl.speed_multiplier.read().await;
        assert!(m <= 1.0);

        ctrl.set_speed_multiplier(-0.5).await; // Below 0.0
        let m = *ctrl.speed_multiplier.read().await;
        assert!(m >= 0.0);
    }

    #[tokio::test]
    async fn test_get_allowed_speed_unlimited() {
        let ctrl = TcpController::new(0);
        let speed = ctrl.get_allowed_speed_kbps().await;
        // Unlimited = 0 * multiplier
        assert_eq!(speed, 0);
    }

    #[tokio::test]
    async fn test_get_allowed_speed_limited() {
        let ctrl = TcpController::new(1000); // 1000 KB/s
        ctrl.set_speed_multiplier(0.5).await;
        let speed = ctrl.get_allowed_speed_kbps().await;
        assert_eq!(speed, 500);
    }

    #[tokio::test]
    async fn test_reset() {
        let ctrl = TcpController::new(0);
        ctrl.set_speed_multiplier(0.3).await;
        ctrl.reset().await;
        let m = *ctrl.speed_multiplier.read().await;
        assert!((m - 1.0).abs() < 0.01);
    }

    #[test]
    fn test_initial_speed_zero() {
        let ctrl = TcpController::new(1000);
        assert_eq!(ctrl.get_current_speed_kbps(), 0);
    }
}
