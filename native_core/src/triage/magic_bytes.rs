// ============================================
// SHADOW CATCHER - Magic Bytes Detector
// Identifies file types from binary signatures
// ============================================

use std::collections::HashMap;

// ─────────────────────────────────────────
// FILE TYPE ENUM
// ─────────────────────────────────────────

/// Detected file type from magic bytes
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum FileType {
    // ── Images ──
    Png,
    Jpeg,
    Gif,
    Bmp,
    Webp,
    Tiff,
    Ico,

    // ── Video ──
    Mp4,
    Mkv,
    Webm,
    Avi,
    Mov,
    Flv,
    Wmv,

    // ── Audio ──
    Mp3,
    Flac,
    Ogg,
    Wav,
    Aac,
    M4a,

    // ── Archives ──
    Zip,
    Rar,
    SevenZip,
    Gzip,
    Bzip2,
    Tar,
    Xz,

    // ── Executables (HIGH RISK) ──
    PeExecutable,    // Windows .exe .dll
    ElfExecutable,   // Linux binary
    MachoExecutable, // macOS binary
    JavaClass,       // .class file

    // ── Scripts (MEDIUM-HIGH RISK) ──
    ShellScript,
    PowerShell,
    BatchFile,
    PythonScript,
    JavaScriptFile,
    PhpScript,
    VbsScript,

    // ── Documents ──
    Pdf,
    MsOfficeOld,  // .doc .xls .ppt
    MsOfficeNew,  // .docx .xlsx .pptx
    Rtf,

    // ── Other ──
    Xml,
    Html,
    Json,
    Utf16Le,
    Utf16Be,

    // ── Unknown ──
    Unknown,
}

impl FileType {
    /// Get risk score for this file type
    /// Returns value in [0.0, 1.0]
    pub fn risk_score(&self) -> f32 {
        match self {
            // Critical risk
            Self::PeExecutable    => 1.0,
            Self::ElfExecutable   => 1.0,
            Self::MachoExecutable => 1.0,
            Self::VbsScript       => 0.9,
            Self::BatchFile       => 0.9,
            Self::PowerShell      => 0.85,
            Self::ShellScript     => 0.8,

            // High risk
            Self::PhpScript       => 0.7,
            Self::JavaClass       => 0.7,
            Self::JavaScriptFile  => 0.6,

            // Medium risk
            Self::Pdf             => 0.35,
            Self::MsOfficeOld     => 0.4,
            Self::MsOfficeNew     => 0.3,
            Self::Rtf             => 0.35,
            Self::PythonScript    => 0.4,
            Self::Zip             => 0.2,
            Self::Rar             => 0.2,
            Self::SevenZip        => 0.2,

            // Low risk
            Self::Mp4 | Self::Mkv | Self::Webm |
            Self::Avi | Self::Mov | Self::Flv => 0.05,

            Self::Mp3 | Self::Flac | Self::Ogg |
            Self::Wav | Self::Aac              => 0.02,

            Self::Png | Self::Jpeg | Self::Gif |
            Self::Bmp | Self::Webp             => 0.01,

            // Unknown is suspicious
            Self::Unknown => 0.5,

            _ => 0.1,
        }
    }

    /// Check if this type is executable
    pub fn is_executable(&self) -> bool {
        matches!(
            self,
            Self::PeExecutable
                | Self::ElfExecutable
                | Self::MachoExecutable
                | Self::JavaClass
        )
    }

    /// Check if this type is a script
    pub fn is_script(&self) -> bool {
        matches!(
            self,
            Self::ShellScript
                | Self::PowerShell
                | Self::BatchFile
                | Self::PythonScript
                | Self::JavaScriptFile
                | Self::PhpScript
                | Self::VbsScript
        )
    }

    /// Human-readable name
    pub fn display_name(&self) -> &'static str {
        match self {
            Self::PeExecutable    => "Windows Executable (PE)",
            Self::ElfExecutable   => "Linux Executable (ELF)",
            Self::MachoExecutable => "macOS Executable (Mach-O)",
            Self::ShellScript     => "Shell Script",
            Self::PowerShell      => "PowerShell Script",
            Self::BatchFile       => "Batch File",
            Self::VbsScript       => "VBScript",
            Self::PhpScript       => "PHP Script",
            Self::JavaScriptFile  => "JavaScript",
            Self::Pdf             => "PDF Document",
            Self::Zip             => "ZIP Archive",
            Self::Mp4             => "MP4 Video",
            Self::Png             => "PNG Image",
            Self::Jpeg            => "JPEG Image",
            Self::Mp3             => "MP3 Audio",
            Self::Unknown         => "Unknown",
            _ => "Unknown Type",
        }
    }
}

impl std::fmt::Display for FileType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.display_name())
    }
}

// ─────────────────────────────────────────
// MAGIC SIGNATURES
// ─────────────────────────────────────────

/// Magic byte signature entry
struct MagicSignature {
    bytes: &'static [u8],
    file_type: FileType,
    offset: usize, // Byte offset where signature appears
}

// ─────────────────────────────────────────
// MAGIC BYTES DETECTOR
// ─────────────────────────────────────────

/// Detects file types from magic bytes
pub struct MagicBytesDetector {
    signatures: Vec<MagicSignature>,
}

impl MagicBytesDetector {
    /// Create a new detector with all known signatures
    pub fn new() -> Self {
        let signatures = vec![
            // ── Executables (checked first - highest priority) ──
            MagicSignature {
                bytes: b"MZ",
                file_type: FileType::PeExecutable,
                offset: 0,
            },
            MagicSignature {
                bytes: b"\x7fELF",
                file_type: FileType::ElfExecutable,
                offset: 0,
            },
            MagicSignature {
                bytes: b"\xca\xfe\xba\xbe",
                file_type: FileType::MachoExecutable,
                offset: 0,
            },
            MagicSignature {
                bytes: b"\xfe\xed\xfa\xce",
                file_type: FileType::MachoExecutable,
                offset: 0,
            },
            MagicSignature {
                bytes: b"\xce\xfa\xed\xfe",
                file_type: FileType::MachoExecutable,
                offset: 0,
            },

            // ── Scripts ──
            MagicSignature {
                bytes: b"#!/bin/sh",
                file_type: FileType::ShellScript,
                offset: 0,
            },
            MagicSignature {
                bytes: b"#!/bin/bash",
                file_type: FileType::ShellScript,
                offset: 0,
            },
            MagicSignature {
                bytes: b"#!/usr/bin/env bash",
                file_type: FileType::ShellScript,
                offset: 0,
            },
            MagicSignature {
                bytes: b"#!/usr/bin/python",
                file_type: FileType::PythonScript,
                offset: 0,
            },
            MagicSignature {
                bytes: b"<?php",
                file_type: FileType::PhpScript,
                offset: 0,
            },

            // ── Images ──
            MagicSignature {
                bytes: b"\x89PNG\r\n\x1a\n",
                file_type: FileType::Png,
                offset: 0,
            },
            MagicSignature {
                bytes: b"\xff\xd8\xff",
                file_type: FileType::Jpeg,
                offset: 0,
            },
            MagicSignature {
                bytes: b"GIF87a",
                file_type: FileType::Gif,
                offset: 0,
            },
            MagicSignature {
                bytes: b"GIF89a",
                file_type: FileType::Gif,
                offset: 0,
            },
            MagicSignature {
                bytes: b"BM",
                file_type: FileType::Bmp,
                offset: 0,
            },
            MagicSignature {
                bytes: b"RIFF",
                file_type: FileType::Webp,
                offset: 0,
            },

            // ── Video ──
            MagicSignature {
                bytes: b"\x1a\x45\xdf\xa3",
                file_type: FileType::Mkv,
                offset: 0,
            },
            MagicSignature {
                bytes: b"ftyp",
                file_type: FileType::Mp4,
                offset: 4,
            },
            MagicSignature {
                bytes: b"FLV\x01",
                file_type: FileType::Flv,
                offset: 0,
            },

            // ── Audio ──
            MagicSignature {
                bytes: b"ID3",
                file_type: FileType::Mp3,
                offset: 0,
            },
            MagicSignature {
                bytes: b"\xff\xfb",
                file_type: FileType::Mp3,
                offset: 0,
            },
            MagicSignature {
                bytes: b"\xff\xf3",
                file_type: FileType::Mp3,
                offset: 0,
            },
            MagicSignature {
                bytes: b"fLaC",
                file_type: FileType::Flac,
                offset: 0,
            },
            MagicSignature {
                bytes: b"OggS",
                file_type: FileType::Ogg,
                offset: 0,
            },
            MagicSignature {
                bytes: b"RIFF",
                file_type: FileType::Wav,
                offset: 0,
            },

            // ── Archives ──
            MagicSignature {
                bytes: b"PK\x03\x04",
                file_type: FileType::Zip,
                offset: 0,
            },
            MagicSignature {
                bytes: b"PK\x05\x06",
                file_type: FileType::Zip,
                offset: 0,
            },
            MagicSignature {
                bytes: b"Rar!\x1a\x07\x00",
                file_type: FileType::Rar,
                offset: 0,
            },
            MagicSignature {
                bytes: b"Rar!\x1a\x07\x01",
                file_type: FileType::Rar,
                offset: 0,
            },
            MagicSignature {
                bytes: b"7z\xbc\xaf\x27\x1c",
                file_type: FileType::SevenZip,
                offset: 0,
            },
            MagicSignature {
                bytes: b"\x1f\x8b",
                file_type: FileType::Gzip,
                offset: 0,
            },
            MagicSignature {
                bytes: b"BZh",
                file_type: FileType::Bzip2,
                offset: 0,
            },

            // ── Documents ──
            MagicSignature {
                bytes: b"%PDF",
                file_type: FileType::Pdf,
                offset: 0,
            },
            MagicSignature {
                bytes: b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1",
                file_type: FileType::MsOfficeOld,
                offset: 0,
            },
            MagicSignature {
                bytes: b"\xef\xbb\xbf",
                file_type: FileType::Utf16Le,
                offset: 0,
            },

            // ── Markup ──
            MagicSignature {
                bytes: b"<?xml",
                file_type: FileType::Xml,
                offset: 0,
            },
            MagicSignature {
                bytes: b"<!DOCTYPE",
                file_type: FileType::Html,
                offset: 0,
            },
            MagicSignature {
                bytes: b"<html",
                file_type: FileType::Html,
                offset: 0,
            },

            // ── Java ──
            MagicSignature {
                bytes: b"\xca\xfe\xba\xbe",
                file_type: FileType::JavaClass,
                offset: 0,
            },
        ];

        Self { signatures }
    }

    /// Detect file type from header bytes
    pub fn detect(&self, header: &[u8]) -> FileType {
        if header.is_empty() {
            return FileType::Unknown;
        }

        for sig in &self.signatures {
            if self.matches(header, sig) {
                return sig.file_type.clone();
            }
        }

        // Try UTF-16 detection
        if header.len() >= 2 {
            match &header[0..2] {
                b"\xff\xfe" => return FileType::Utf16Le,
                b"\xfe\xff" => return FileType::Utf16Be,
                _ => {}
            }
        }

        FileType::Unknown
    }

    /// Check if header matches a signature at the given offset
    fn matches(&self, header: &[u8], sig: &MagicSignature) -> bool {
        let start = sig.offset;
        let end = start + sig.bytes.len();

        if end > header.len() {
            return false;
        }

        &header[start..end] == sig.bytes
    }

    /// Get all supported file type signatures (for testing)
    pub fn get_signature_count(&self) -> usize {
        self.signatures.len()
    }

    /// Detect and return risk score directly
    pub fn get_risk_score(&self, header: &[u8]) -> f32 {
        self.detect(header).risk_score()
    }

    /// Check if header starts with executable magic bytes
    pub fn is_executable(&self, header: &[u8]) -> bool {
        self.detect(header).is_executable()
    }

    /// Check if header starts with script magic bytes
    pub fn is_script(&self, header: &[u8]) -> bool {
        self.detect(header).is_script()
    }
}

impl Default for MagicBytesDetector {
    fn default() -> Self {
        Self::new()
    }
}

// ─────────────────────────────────────────
// TESTS
// ─────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn detector() -> MagicBytesDetector {
        MagicBytesDetector::new()
    }

    #[test]
    fn test_detects_png() {
        let header = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR";
        assert_eq!(detector().detect(header), FileType::Png);
    }

    #[test]
    fn test_detects_pe_executable() {
        let header = b"MZ\x90\x00\x03\x00\x00\x00";
        assert_eq!(detector().detect(header), FileType::PeExecutable);
    }

    #[test]
    fn test_detects_elf() {
        let header = b"\x7fELF\x02\x01\x01\x00";
        assert_eq!(detector().detect(header), FileType::ElfExecutable);
    }

    #[test]
    fn test_detects_pdf() {
        let header = b"%PDF-1.7\n";
        assert_eq!(detector().detect(header), FileType::Pdf);
    }

    #[test]
    fn test_detects_zip() {
        let header = b"PK\x03\x04\x14\x00\x00\x00";
        assert_eq!(detector().detect(header), FileType::Zip);
    }

    #[test]
    fn test_detects_mp3() {
        let header = b"ID3\x03\x00\x00\x00\x00";
        assert_eq!(detector().detect(header), FileType::Mp3);
    }

    #[test]
    fn test_unknown_returns_unknown() {
        let header = b"\x42\x43\x44\x45\x46\x47";
        assert_eq!(detector().detect(header), FileType::Unknown);
    }

    #[test]
    fn test_empty_returns_unknown() {
        assert_eq!(detector().detect(b""), FileType::Unknown);
    }

    #[test]
    fn test_pe_is_executable() {
        let header = b"MZ\x90\x00";
        assert!(detector().is_executable(header));
    }

    #[test]
    fn test_png_not_executable() {
        let header = b"\x89PNG\r\n\x1a\n";
        assert!(!detector().is_executable(header));
    }

    #[test]
    fn test_shell_script_is_script() {
        let header = b"#!/bin/bash\necho hello";
        assert!(detector().is_script(header));
    }

    #[test]
    fn test_pe_high_risk() {
        assert_eq!(FileType::PeExecutable.risk_score(), 1.0);
    }

    #[test]
    fn test_png_low_risk() {
        assert!(FileType::Png.risk_score() < 0.1);
    }

    #[test]
    fn test_signature_count_reasonable() {
        let d = detector();
        assert!(d.get_signature_count() > 20);
    }
}
