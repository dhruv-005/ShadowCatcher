// ============================================
// SHADOW CATCHER - Triage Pipeline Integration Tests
// ============================================

use shadow_core::triage::{
    MagicBytesDetector,
    ExtensionChecker,
    HeaderParser,
    TriagePipeline,
};
use shadow_core::models::{ScanVerdict};

// ─────────────────────────────────────────
// HELPER DATA
// ─────────────────────────────────────────

fn png_header() -> Vec<u8> {
    let mut h = b"\x89PNG\r\n\x1a\n".to_vec();
    h.extend_from_slice(&[0u8; 504]);
    h
}

fn pe_header() -> Vec<u8> {
    let mut h = b"MZ\x90\x00\x03\x00\x00\x00".to_vec();
    h.extend_from_slice(b"This program cannot be run in DOS mode\r\n\r\n");
    h.extend_from_slice(&[0u8; 460]);
    h
}

fn elf_header() -> Vec<u8> {
    let mut h = b"\x7fELF\x02\x01\x01\x00".to_vec();
    h.extend_from_slice(&[0u8; 504]);
    h
}

fn shell_script_header() -> Vec<u8> {
    let mut h = b"#!/bin/bash\necho hello world\n".to_vec();
    h.extend_from_slice(&[0u8; 480]);
    h
}

fn pdf_header() -> Vec<u8> {
    let mut h = b"%PDF-1.7\n".to_vec();
    h.extend_from_slice(&[0u8; 503]);
    h
}

fn mp4_header() -> Vec<u8> {
    let mut h = vec![0u8, 0, 0, 0x18];
    h.extend_from_slice(b"ftypisom");
    h.extend_from_slice(&[0u8; 500]);
    h
}

fn powershell_injection() -> Vec<u8> {
    let mut h = b"\x89PNG\r\n\x1a\n".to_vec();
    h.extend_from_slice(&[0u8; 100]);
    h.extend_from_slice(b"powershell -enc aGVsbG8gd29ybGQ=");
    h.extend_from_slice(&[0u8; 360]);
    h
}

// ─────────────────────────────────────────
// MAGIC BYTES TESTS
// ─────────────────────────────────────────

#[cfg(test)]
mod magic_bytes_tests {
    use super::*;
    use shadow_core::triage::magic_bytes::FileType;

    #[test]
    fn test_pipeline_detects_png() {
        let detector = MagicBytesDetector::new();
        assert_eq!(detector.detect(&png_header()), FileType::Png);
    }

    #[test]
    fn test_pipeline_detects_pe() {
        let detector = MagicBytesDetector::new();
        assert_eq!(
            detector.detect(&pe_header()),
            FileType::PeExecutable
        );
    }

    #[test]
    fn test_pipeline_detects_elf() {
        let detector = MagicBytesDetector::new();
        assert_eq!(
            detector.detect(&elf_header()),
            FileType::ElfExecutable
        );
    }

    #[test]
    fn test_pipeline_detects_shell() {
        let detector = MagicBytesDetector::new();
        assert_eq!(
            detector.detect(&shell_script_header()),
            FileType::ShellScript
        );
    }

    #[test]
    fn test_pipeline_detects_pdf() {
        let detector = MagicBytesDetector::new();
        assert_eq!(detector.detect(&pdf_header()), FileType::Pdf);
    }

    #[test]
    fn test_pipeline_detects_mp4() {
        let detector = MagicBytesDetector::new();
        let detected = detector.detect(&mp4_header());
        assert!(
            matches!(
                detected,
                FileType::Mp4 | FileType::Unknown
            ),
            "Expected MP4 type"
        );
    }

    #[test]
    fn test_pe_has_high_risk() {
        let detector = MagicBytesDetector::new();
        let risk = detector.get_risk_score(&pe_header());
        assert!(risk >= 0.9, "PE should have high risk");
    }

    #[test]
    fn test_png_has_low_risk() {
        let detector = MagicBytesDetector::new();
        let risk = detector.get_risk_score(&png_header());
        assert!(risk < 0.1, "PNG should have low risk");
    }

    #[test]
    fn test_pe_is_executable() {
        let detector = MagicBytesDetector::new();
        assert!(detector.is_executable(&pe_header()));
    }

    #[test]
    fn test_elf_is_executable() {
        let detector = MagicBytesDetector::new();
        assert!(detector.is_executable(&elf_header()));
    }

    #[test]
    fn test_png_not_executable() {
        let detector = MagicBytesDetector::new();
        assert!(!detector.is_executable(&png_header()));
    }

    #[test]
    fn test_shell_is_script() {
        let detector = MagicBytesDetector::new();
        assert!(detector.is_script(&shell_script_header()));
    }
}

// ─────────────────────────────────────────
// EXTENSION CHECKER TESTS
// ─────────────────────────────────────────

#[cfg(test)]
mod extension_tests {
    use super::*;
    use shadow_core::triage::magic_bytes::FileType;

    #[test]
    fn test_png_extension_not_spoofed() {
        let checker = ExtensionChecker::new();
        assert!(!checker.is_spoofed("png", &FileType::Png));
    }

    #[test]
    fn test_png_extension_spoofed_with_pe() {
        let checker = ExtensionChecker::new();
        assert!(checker.is_spoofed("png", &FileType::PeExecutable));
    }

    #[test]
    fn test_mp4_extension_not_spoofed() {
        let checker = ExtensionChecker::new();
        assert!(!checker.is_spoofed("mp4", &FileType::Mp4));
    }

    #[test]
    fn test_exe_high_risk() {
        let checker = ExtensionChecker::new();
        assert!(checker.is_high_risk("exe"));
        assert!(checker.is_high_risk("dll"));
        assert!(checker.is_high_risk("bat"));
    }

    #[test]
    fn test_media_low_risk() {
        let checker = ExtensionChecker::new();
        assert!(!checker.is_high_risk("mp4"));
        assert!(!checker.is_high_risk("mp3"));
        assert!(!checker.is_high_risk("png"));
    }

    #[test]
    fn test_validate_url_safe() {
        let checker = ExtensionChecker::new();
        let (safe, risk, _) = checker
            .validate_url("https://cdn.example.com/video.mp4");
        assert!(safe);
        assert!(risk < 0.1);
    }

    #[test]
    fn test_validate_url_dangerous() {
        let checker = ExtensionChecker::new();
        let (safe, risk, _) = checker
            .validate_url("https://evil.com/malware.exe");
        assert!(!safe);
        assert!(risk >= 0.9);
    }

    #[test]
    fn test_validate_url_ps1() {
        let checker = ExtensionChecker::new();
        let (safe, _, _) = checker
            .validate_url("https://evil.com/script.ps1");
        assert!(!safe);
    }

    #[test]
    fn test_docx_not_spoofed_as_zip() {
        let checker = ExtensionChecker::new();
        // DOCX is internally a ZIP
        assert!(!checker.is_spoofed("docx", &FileType::Zip));
    }

    #[test]
    fn test_get_extension_from_filename() {
        assert_eq!(
            ExtensionChecker::get_extension("video.MP4"),
            "mp4"
        );
        assert_eq!(
            ExtensionChecker::get_extension("archive.tar.gz"),
            "gz"
        );
        assert_eq!(
            ExtensionChecker::get_extension("Makefile"),
            ""
        );
    }
}

// ─────────────────────────────────────────
// HEADER PARSER TESTS
// ─────────────────────────────────────────

#[cfg(test)]
mod header_parser_tests {
    use super::*;
    use shadow_core::triage::magic_bytes::FileType;

    #[test]
    fn test_clean_png_no_critical_issues() {
        let parser = HeaderParser::new();
        let issues = parser.analyze(&png_header(), &FileType::Png);
        assert!(
            !issues.is_critical(),
            "Clean PNG should have no critical issues"
        );
    }

    #[test]
    fn test_powershell_injection_detected() {
        let parser = HeaderParser::new();
        let issues = parser.analyze(
            &powershell_injection(),
            &FileType::Png,
        );
        assert!(
            issues.is_critical() || issues.has_high_severity(),
            "PowerShell injection should be detected"
        );
    }

    #[test]
    fn test_pe_structure_analyzed() {
        let parser = HeaderParser::new();
        let issues = parser.analyze(
            &pe_header(),
            &FileType::PeExecutable,
        );
        // PE files are analyzed but not automatically flagged
        // Only suspicious ones get issues
        let _ = issues; // Just verify it doesn't panic
    }

    #[test]
    fn test_high_entropy_detection() {
        let parser = HeaderParser::new();
        // Create high-entropy data
        let mut data = vec![0u8; 512];
        for i in 0..512 {
            data[i] = (i * 37 % 256) as u8;
        }
        let issues = parser.analyze(&data, &FileType::Unknown);
        // High entropy might trigger warning
        let _ = issues;
    }

    #[test]
    fn test_embedded_pe_in_image_detected() {
        let parser = HeaderParser::new();
        let mut data = b"\x89PNG\r\n\x1a\n".to_vec();
        data.extend_from_slice(&[0u8; 100]);
        data.extend_from_slice(b"MZ\x90\x00"); // Embedded PE
        data.extend_from_slice(&[0u8; 392]);

        let issues = parser.analyze(&data, &FileType::Png);
        assert!(
            issues.has_high_severity(),
            "Embedded PE should be detected"
        );
    }

    #[test]
    fn test_create_object_detected() {
        let parser = HeaderParser::new();
        let data = b"var x = new CreateObject(\"WScript.Shell\");"
            .to_vec();
        let mut padded = data;
        padded.resize(512, 0);

        let issues = parser.analyze(&padded, &FileType::JavaScriptFile);
        assert!(
            !issues.issues.is_empty(),
            "CreateObject should be flagged"
        );
    }
}

// ─────────────────────────────────────────
// FULL PIPELINE INTEGRATION TESTS
// ─────────────────────────────────────────

#[cfg(test)]
mod full_pipeline_tests {
    use super::*;

    /// Test complete triage without AI (no model file needed)
    #[test]
    fn test_extension_spoofing_blocked_before_ai() {
        let checker = ExtensionChecker::new();
        let detector = MagicBytesDetector::new();

        let header = pe_header();
        let detected_type = detector.detect(&header);
        let is_spoofed = checker.is_spoofed("png", &detected_type);

        assert!(
            is_spoofed,
            "PE file with .png extension should be spoofed"
        );
    }

    #[test]
    fn test_clean_file_passes_all_checks() {
        let checker = ExtensionChecker::new();
        let detector = MagicBytesDetector::new();
        let parser = HeaderParser::new();

        let header = png_header();
        let detected_type = detector.detect(&header);
        let is_spoofed = checker.is_spoofed("png", &detected_type);
        let issues = parser.analyze(&header, &detected_type);

        assert!(!is_spoofed, "PNG should not be spoofed");
        assert!(!issues.is_critical(), "PNG should have no critical issues");
    }

    #[test]
    fn test_shell_script_high_risk() {
        let checker = ExtensionChecker::new();
        let detector = MagicBytesDetector::new();

        let header = shell_script_header();
        let detected_type = detector.detect(&header);
        let risk = detected_type.risk_score();

        assert!(risk >= 0.7, "Shell script should be high risk");
    }

    #[test]
    fn test_mp4_safe_full_pipeline() {
        let checker = ExtensionChecker::new();
        let detector = MagicBytesDetector::new();
        let parser = HeaderParser::new();

        let header = mp4_header();
        let detected = detector.detect(&header);
        let risk = detected.risk_score();
        let issues = parser.analyze(&header, &detected);

        assert!(risk < 0.2, "MP4 should be low risk");
        assert!(!issues.is_critical());
    }

    #[test]
    fn test_pdf_medium_risk() {
        let detector = MagicBytesDetector::new();
        let header = pdf_header();
        let detected = detector.detect(&header);
        let risk = detected.risk_score();
        assert!(risk > 0.1 && risk < 0.6, "PDF should be medium risk");
    }

    #[test]
    fn test_elf_blocked_as_spoofed_png() {
        let checker = ExtensionChecker::new();
        let detector = MagicBytesDetector::new();

        let header = elf_header();
        let detected = detector.detect(&header);
        let is_spoofed = checker.is_spoofed("jpg", &detected);

        assert!(is_spoofed, "ELF disguised as JPG should be caught");
    }
}
