// ============================================
// SHADOW CATCHER - Utils Module
// ============================================

pub mod config;
pub mod error;
pub mod logger;

pub use config::AppConfig;
pub use error::{ShadowError, ShadowResult};
pub use logger::init as init_logger;
