// ============================================
// SHADOW CATCHER - Logger Setup (Rust)
// ============================================

use std::path::PathBuf;
use tracing_subscriber::{
    fmt,
    layer::SubscriberExt,
    util::SubscriberInitExt,
    EnvFilter,
};
use tracing_appender::rolling;

use crate::utils::error::{ShadowError, ShadowResult};

/// Initialize the logging system
pub fn init(log_level: &str) -> ShadowResult<()> {
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| {
            EnvFilter::new(format!(
                "shadow_core={},info",
                log_level
            ))
        });

    let fmt_layer = fmt::layer()
        .with_target(true)
        .with_thread_ids(true)
        .with_line_number(true)
        .compact();

    tracing_subscriber::registry()
        .with(filter)
        .with(fmt_layer)
        .try_init()
        .map_err(|e| ShadowError::Internal(
            format!("Failed to init logger: {}", e)
        ))?;

    tracing::info!(
        "Shadow Catcher core v{} started",
        env!("CARGO_PKG_VERSION")
    );

    Ok(())
}

/// Initialize logger with file output
pub fn init_with_file(
    log_level: &str,
    log_dir: &str,
) -> ShadowResult<()> {
    std::fs::create_dir_all(log_dir)
        .map_err(|e| ShadowError::Io(e.to_string()))?;

    let file_appender = rolling::daily(log_dir, "shadow_core.log");
    let (non_blocking, _guard) =
        tracing_appender::non_blocking(file_appender);

    let filter = EnvFilter::new(format!(
        "shadow_core={},info",
        log_level
    ));

    let file_layer = fmt::layer()
        .with_writer(non_blocking)
        .with_ansi(false)
        .with_target(true)
        .json();

    let console_layer = fmt::layer()
        .with_target(true)
        .compact();

    tracing_subscriber::registry()
        .with(filter)
        .with(file_layer)
        .with(console_layer)
        .try_init()
        .map_err(|e| ShadowError::Internal(
            format!("Failed to init logger: {}", e)
        ))?;

    tracing::info!("Logging initialized: {}", log_dir);
    Ok(())
}

// ─────────────────────────────────────────
// TESTS
// ─────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_logger_init() {
        // Logger init may fail if already initialized in test suite
        // That is acceptable
        let _ = init("debug");
    }
}
