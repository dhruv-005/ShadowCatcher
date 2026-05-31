// ============================================
// SHADOW CATCHER - Triage Module
// Security scanning pipeline
// ============================================

pub mod extension_checker;
pub mod header_parser;
pub mod magic_bytes;
pub mod onnx_runner;

pub use extension_checker::ExtensionChecker;
pub use header_parser::HeaderParser;
pub use magic_bytes::MagicBytesDetector;
pub use onnx_runner::OnnxRunner;

use crate::models::{ScanResult, ScanVerdict};
use crate::utils::error::ShadowResult;

// ─────────────────────────────────────────
// TRIAGE PIPELINE
// ─────────────────────────────────────────

/// Complete triage pipeline that runs all checks
/// in order from fastest to slowest
pub struct TriagePipeline {
    magic_detector: MagicBytesDetector,
    extension_checker: ExtensionChecker,
    header_parser: HeaderParser,
    onnx_runner: OnnxRunner,
}

impl TriagePipeline {
    /// Create a new triage pipeline
    pub fn new(onnx_model_path: &str) -> ShadowResult<Self> {
        Ok(Self {
            magic_detector: MagicBytesDetector::new(),
            extension_checker: ExtensionChecker::new(),
            header_parser: HeaderParser::new(),
            onnx_runner: OnnxRunner::new(onnx_model_path)?,
        })
    }

    /// Run complete triage on a file
    ///
    /// Pipeline order:
    /// 1. Magic bytes check (fastest - <1ms)
    /// 2. Extension check (<1ms)
    /// 3. Header parse (<5ms)
    /// 4. AI scan (~50ms)
    pub fn scan(
        &self,
        header_bytes: &[u8],
        filename: &str,
        file_size: u64,
    ) -> ShadowResult<ScanResult> {
        // Step 1: Magic bytes detection
        let detected_type = self.magic_detector.detect(header_bytes);

        // Step 2: Extension check
        let extension = ExtensionChecker::get_extension(filename);
        let ext_risk = self.extension_checker.get_risk_score(&extension);

        // Step 3: Check for extension spoofing
        let is_spoofed = self.extension_checker.is_spoofed(
            &extension,
            &detected_type,
        );

        if is_spoofed {
            return Ok(ScanResult {
                verdict: ScanVerdict::Malicious,
                confidence: 0.99,
                threat_name: Some("ExtensionSpoofing".to_string()),
                detected_type: detected_type.to_string(),
                file_size,
                scan_duration_ms: 0,
            });
        }

        // Step 4: Header structure analysis
        let header_issues = self.header_parser.analyze(
            header_bytes,
            &detected_type,
        );

        if header_issues.is_critical() {
            return Ok(ScanResult {
                verdict: ScanVerdict::Malicious,
                confidence: 0.95,
                threat_name: header_issues.threat_name,
                detected_type: detected_type.to_string(),
                file_size,
                scan_duration_ms: 0,
            });
        }

        // Step 5: AI model scan
        let ai_result = self.onnx_runner.scan(header_bytes)?;

        Ok(ai_result)
    }
}
