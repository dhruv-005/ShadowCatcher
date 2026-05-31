// ============================================
// SHADOW CATCHER - Magic Bytes Unit Tests
// ============================================

use shadow_core::triage::magic_bytes::{
    MagicBytesDetector,
    FileType,
};

fn detector() -> MagicBytesDetector {
    MagicBytesDetector::new()
}

// ─────────────────────────────────────────
// IMAGE DETECTION TESTS
// ─────────────────────────────────────────

#[test]
fn test_png_detection() {
    let header = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR";
    assert_eq!(detector().detect(header), FileType::Png);
}

#[test]
fn test_jpeg_detection() {
    let header = b"\xff\xd8\xff\xe0\x00\x10JFIF";
    assert_eq!(detector().detect(header), FileType::Jpeg);
}

#[test]
fn test_gif87a_detection() {
    let header = b"GIF87a\x01\x00\x01\x00";
    assert_eq!(detector().detect(header), FileType::Gif);
}

#[test]
fn test_gif89a_detection() {
    let header = b"GIF89a\x10\x00\x10\x00";
    assert_eq!(detector().detect(header), FileType::Gif);
}

#[test]
fn test_bmp_detection() {
    let header = b"BM\x36\x04\x00\x00\x00\x00";
    assert_eq!(detector().detect(header), FileType::Bmp);
}

// ─────────────────────────────────────────
// VIDEO DETECTION TESTS
// ─────────────────────────────────────────

#[test]
fn test_mkv_detection() {
    let header = b"\x1a\x45\xdf\xa3\x9f\x42\x86\x81";
    assert_eq!(detector().detect(header), FileType::Mkv);
}

#[test]
fn test_flv_detection() {
    let header = b"FLV\x01\x05\x00\x00\x00\x09";
    assert_eq!(detector().detect(header), FileType::Flv);
}

// ─────────────────────────────────────────
// AUDIO DETECTION TESTS
// ─────────────────────────────────────────

#[test]
fn test_mp3_id3_detection() {
    let header = b"ID3\x03\x00\x00\x00\x00\x00\x00";
    assert_eq!(detector().detect(header), FileType::Mp3);
}

#[test]
fn test_mp3_raw_detection() {
    let header = b"\xff\xfb\x90\x00\x00\x00\x00\x00";
    assert_eq!(detector().detect(header), FileType::Mp3);
}

#[test]
fn test_flac_detection() {
    let header = b"fLaC\x00\x00\x00\x22\x00\x00";
    assert_eq!(detector().detect(header), FileType::Flac);
}

#[test]
fn test_ogg_detection() {
    let header = b"OggS\x00\x02\x00\x00\x00\x00";
    assert_eq!(detector().detect(header), FileType::Ogg);
}

// ─────────────────────────────────────────
// EXECUTABLE DETECTION TESTS
// ─────────────────────────────────────────

#[test]
fn test_pe_executable_detection() {
    let header = b"MZ\x90\x00\x03\x00\x00\x00";
    assert_eq!(detector().detect(header), FileType::PeExecutable);
}

#[test]
fn test_elf_executable_detection() {
    let header = b"\x7fELF\x02\x01\x01\x00\x00\x00";
    assert_eq!(detector().detect(header), FileType::ElfExecutable);
}

#[test]
fn test_macho_detection() {
    let header = b"\xca\xfe\xba\xbe\x00\x00\x00\x02";
    assert_eq!(detector().detect(header), FileType::MachoExecutable);
}

// ─────────────────────────────────────────
// SCRIPT DETECTION TESTS
// ─────────────────────────────────────────

#[test]
fn test_bash_script_detection() {
    let header = b"#!/bin/bash\necho hello";
    assert_eq!(detector().detect(header), FileType::ShellScript);
}

#[test]
fn test_sh_script_detection() {
    let header = b"#!/bin/sh\necho hello";
    assert_eq!(detector().detect(header), FileType::ShellScript);
}

#[test]
fn test_python_script_detection() {
    let header = b"#!/usr/bin/python\nprint('hello')";
    assert_eq!(detector().detect(header), FileType::PythonScript);
}

#[test]
fn test_php_script_detection() {
    let header = b"<?php echo 'hello'; ?>";
    assert_eq!(detector().detect(header), FileType::PhpScript);
}

// ─────────────────────────────────────────
// ARCHIVE DETECTION TESTS
// ─────────────────────────────────────────

#[test]
fn test_zip_detection() {
    let header = b"PK\x03\x04\x14\x00\x00\x00";
    assert_eq!(detector().detect(header), FileType::Zip);
}

#[test]
fn test_rar_detection() {
    let header = b"Rar!\x1a\x07\x00\x00";
    assert_eq!(detector().detect(header), FileType::Rar);
}

#[test]
fn test_7zip_detection() {
    let header = b"7z\xbc\xaf\x27\x1c\x00\x03";
    assert_eq!(detector().detect(header), FileType::SevenZip);
}

#[test]
fn test_gzip_detection() {
    let header = b"\x1f\x8b\x08\x00\x00\x00\x00\x00";
    assert_eq!(detector().detect(header), FileType::Gzip);
}

// ─────────────────────────────────────────
// DOCUMENT DETECTION TESTS
// ─────────────────────────────────────────

#[test]
fn test_pdf_detection() {
    let header = b"%PDF-1.7\n%\xe2\xe3\xcf\xd3";
    assert_eq!(detector().detect(header), FileType::Pdf);
}

#[test]
fn test_ms_office_old_detection() {
    let header = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1";
    assert_eq!(detector().detect(header), FileType::MsOfficeOld);
}

// ─────────────────────────────────────────
// EDGE CASE TESTS
// ─────────────────────────────────────────

#[test]
fn test_empty_bytes_unknown() {
    assert_eq!(detector().detect(b""), FileType::Unknown);
}

#[test]
fn test_single_byte_unknown() {
    assert_eq!(detector().detect(b"\x00"), FileType::Unknown);
}

#[test]
fn test_all_zeros_unknown() {
    assert_eq!(detector().detect(&[0u8; 16]), FileType::Unknown);
}

#[test]
fn test_random_bytes_unknown() {
    let data = b"\x42\x43\x44\x45\x46\x47\x48\x49";
    assert_eq!(detector().detect(data), FileType::Unknown);
}

#[test]
fn test_truncated_signature() {
    // Only first byte of PNG magic
    assert_eq!(detector().detect(b"\x89"), FileType::Unknown);
}

// ─────────────────────────────────────────
// RISK SCORE TESTS
// ─────────────────────────────────────────

#[test]
fn test_pe_risk_score_maximum() {
    assert_eq!(FileType::PeExecutable.risk_score(), 1.0);
}

#[test]
fn test_elf_risk_score_maximum() {
    assert_eq!(FileType::ElfExecutable.risk_score(), 1.0);
}

#[test]
fn test_png_risk_score_minimal() {
    assert!(FileType::Png.risk_score() < 0.05);
}

#[test]
fn test_jpeg_risk_score_minimal() {
    assert!(FileType::Jpeg.risk_score() < 0.05);
}

#[test]
fn test_shell_script_high_risk() {
    assert!(FileType::ShellScript.risk_score() >= 0.7);
}

#[test]
fn test_unknown_medium_risk() {
    assert!(FileType::Unknown.risk_score() >= 0.4);
}

// ─────────────────────────────────────────
// TYPE CLASSIFICATION TESTS
// ─────────────────────────────────────────

#[test]
fn test_executables_are_executable() {
    assert!(FileType::PeExecutable.is_executable());
    assert!(FileType::ElfExecutable.is_executable());
    assert!(FileType::MachoExecutable.is_executable());
}

#[test]
fn test_non_executables_not_executable() {
    assert!(!FileType::Png.is_executable());
    assert!(!FileType::Mp4.is_executable());
    assert!(!FileType::Pdf.is_executable());
    assert!(!FileType::Zip.is_executable());
}

#[test]
fn test_scripts_are_scripts() {
    assert!(FileType::ShellScript.is_script());
    assert!(FileType::PowerShell.is_script());
    assert!(FileType::PhpScript.is_script());
    assert!(FileType::VbsScript.is_script());
}

#[test]
fn test_non_scripts_not_scripts() {
    assert!(!FileType::Png.is_script());
    assert!(!FileType::Mp4.is_script());
    assert!(!FileType::PeExecutable.is_script());
}

#[test]
fn test_signature_count_sufficient() {
    let d = detector();
    assert!(
        d.get_signature_count() >= 25,
        "Should have at least 25 signatures"
    );
}

#[test]
fn test_get_risk_score_from_bytes() {
    let d = detector();
    let pe_risk = d.get_risk_score(b"MZ\x90\x00");
    let png_risk = d.get_risk_score(b"\x89PNG\r\n\x1a\n");
    assert!(pe_risk > png_risk);
}
