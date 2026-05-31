// ============================================
// SHADOW CATCHER - Library Root
// Entry point for the native Rust core
// ============================================

#![warn(clippy::all)]
#![warn(clippy::pedantic)]
#![allow(clippy::module_name_repetitions)]
#![allow(clippy::must_use_candidate)]

// ─────────────────────────────────────────
// MODULE DECLARATIONS
// ─────────────────────────────────────────

pub mod api;
pub mod models;
pub mod network;
pub mod stream;
pub mod throttler;
pub mod triage;
pub mod utils;

// ─────────────────────────────────────────
// RE-EXPORTS
// ─────────────────────────────────────────

pub use api::ShadowApi;
pub use models::{
    DownloadTask,
    DownloadStatus,
    ScanResult,
    ScanVerdict,
    ThreatReport,
};
pub use utils::error::{ShadowError, ShadowResult};
pub use utils::config::AppConfig;

// ─────────────────────────────────────────
// VERSION INFO
// ─────────────────────────────────────────

/// Current version of the Shadow Catcher core engine
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Build timestamp (set by build.rs)
pub const BUILD_TIMESTAMP: &str = env!(
    "SHADOW_BUILD_TIMESTAMP",
    "unknown"
);

/// Git commit hash (set by build.rs)
pub const GIT_HASH: &str = env!(
    "SHADOW_GIT_HASH",
    "unknown"
);

// ─────────────────────────────────────────
// FLUTTER RUST BRIDGE
// ─────────────────────────────────────────

use flutter_rust_bridge::frb;

/// Initialize the Shadow Catcher core engine.
/// Must be called once before any other API calls.
///
/// # Arguments
/// * `config_json` - JSON string of AppConfig
///
/// # Returns
/// * `Ok(())` on success
/// * `Err(String)` with error message on failure
#[frb(sync)]
pub fn initialize_core(config_json: String) -> Result<(), String> {
    api::initialize(config_json)
        .map_err(|e| e.to_string())
}

/// Get the current version of the core engine.
#[frb(sync)]
pub fn get_version() -> String {
    format!(
        "{} (build: {}, git: {})",
        VERSION,
        BUILD_TIMESTAMP,
        GIT_HASH,
    )
}

/// Shutdown the core engine gracefully.
#[frb(sync)]
pub fn shutdown_core() {
    api::shutdown();
}

// ─────────────────────────────────────────
// GLOBAL RUNTIME
// ─────────────────────────────────────────

use once_cell::sync::OnceCell;
use tokio::runtime::Runtime;

/// Global Tokio runtime for async operations
static RUNTIME: OnceCell<Runtime> = OnceCell::new();

/// Get or create the global async runtime
pub fn get_runtime() -> &'static Runtime {
    RUNTIME.get_or_init(|| {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(4)
            .thread_name("shadow-worker")
            .enable_all()
            .build()
            .expect("Failed to build Tokio runtime")
    })
}

/// Execute an async future on the global runtime (blocking)
pub fn block_on<F, T>(future: F) -> T
where
    F: std::future::Future<Output = T>,
{
    get_runtime().block_on(future)
}

// ─────────────────────────────────────────
// TESTS
// ─────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version_not_empty() {
        assert!(!VERSION.is_empty());
    }

    #[test]
    fn test_runtime_creation() {
        let rt = get_runtime();
        let result = rt.block_on(async { 42u32 });
        assert_eq!(result, 42);
    }

    #[test]
    fn test_block_on() {
        let result = block_on(async { "shadow_catcher" });
        assert_eq!(result, "shadow_catcher");
    }
}
