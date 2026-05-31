// ============================================
// SHADOW CATCHER - Extension Checker
// Validates file extensions against magic bytes
// ============================================

use std::collections::HashMap;
use crate::triage::magic_bytes::FileType;

// ─────────────────────────────────────────
// EXTENSION CHECKER
// ─────────────────────────────────────────

/// Validates file extensions and detects spoofing
pub struct ExtensionChecker {
    /// Maps extension → expected file types
    extension_type_map: HashMap<&'static str, Vec<FileType>>,
    /// Maps extension → risk score
    extension_risk_map: HashMap<&'static str, f32>,
}

impl ExtensionChecker {
    /// Create a new extension checker
    pub fn new() -> Self {
        let mut extension_type_map: HashMap<&'static str, Vec<FileType>> =
            HashMap::new();

        // ── Image extensions ──
        extension_type_map.insert("png",  vec![FileType::Png]);
        extension_type_map.insert("jpg",  vec![FileType::Jpeg]);
        extension_type_map.insert("jpeg", vec![FileType::Jpeg]);
        extension_type_map.insert("gif",  vec![FileType::Gif]);
        extension_type_map.insert("bmp",  vec![FileType::Bmp]);
        extension_type_map.insert("webp", vec![FileType::Webp]);
        extension_type_map.insert("tiff", vec![FileType::Tiff]);
        extension_type_map.insert("tif",  vec![FileType::Tiff]);
        extension_type_map.insert("ico",  vec![FileType::Ico]);
        extension_type_map.insert("svg",  vec![FileType::Xml, FileType::Html]);

        // ── Video extensions ──
        extension_type_map.insert("mp4",  vec![FileType::Mp4]);
        extension_type_map.insert("m4v",  vec![FileType::Mp4]);
        extension_type_map.insert("mkv",  vec![FileType::Mkv]);
        extension_type_map.insert("webm", vec![FileType::Webm]);
        extension_type_map.insert("avi",  vec![FileType::Avi]);
        extension_type_map.insert("mov",  vec![FileType::Mov]);
        extension_type_map.insert("flv",  vec![FileType::Flv]);
        extension_type_map.insert("wmv",  vec![FileType::Wmv]);

        // ── Audio extensions ──
        extension_type_map.insert("mp3",  vec![FileType::Mp3]);
        extension_type_map.insert("flac", vec![FileType::Flac]);
        extension_type_map.insert("ogg",  vec![FileType::Ogg]);
        extension_type_map.insert("wav",  vec![FileType::Wav]);
        extension_type_map.insert("aac",  vec![FileType::Aac]);
        extension_type_map.insert("m4a",  vec![FileType::M4a]);

        // ── Archive extensions ──
        extension_type_map.insert("zip",  vec![FileType::Zip]);
        extension_type_map.insert("rar",  vec![FileType::Rar]);
        extension_type_map.insert("7z",   vec![FileType::SevenZip]);
        extension_type_map.insert("gz",   vec![FileType::Gzip]);
        extension_type_map.insert("bz2",  vec![FileType::Bzip2]);
        extension_type_map.insert("tar",  vec![FileType::Tar]);
        extension_type_map.insert("xz",   vec![FileType::Xz]);

        // ── Executable extensions (HIGH RISK) ──
        extension_type_map.insert("exe",  vec![FileType::PeExecutable]);
        extension_type_map.insert("dll",  vec![FileType::PeExecutable]);
        extension_type_map.insert("scr",  vec![FileType::PeExecutable]);
        extension_type_map.insert("com",  vec![FileType::PeExecutable]);
        extension_type_map.insert("pif",  vec![FileType::PeExecutable]);
        extension_type_map.insert("so",   vec![FileType::ElfExecutable]);
        extension_type_map.insert("dylib",vec![FileType::MachoExecutable]);

        // ── Script extensions ──
        extension_type_map.insert("sh",   vec![FileType::ShellScript]);
        extension_type_map.insert("bash", vec![FileType::ShellScript]);
        extension_type_map.insert("zsh",  vec![FileType::ShellScript]);
        extension_type_map.insert("ps1",  vec![FileType::PowerShell]);
        extension_type_map.insert("bat",  vec![FileType::BatchFile]);
        extension_type_map.insert("cmd",  vec![FileType::BatchFile]);
        extension_type_map.insert("py",   vec![FileType::PythonScript]);
        extension_type_map.insert("js",   vec![FileType::JavaScriptFile]);
        extension_type_map.insert("php",  vec![FileType::PhpScript]);
        extension_type_map.insert("vbs",  vec![FileType::VbsScript]);

        // ── Document extensions ──
        extension_type_map.insert("pdf",  vec![FileType::Pdf]);
        extension_type_map.insert("doc",  vec![FileType::MsOfficeOld]);
        extension_type_map.insert("xls",  vec![FileType::MsOfficeOld]);
        extension_type_map.insert("ppt",  vec![FileType::MsOfficeOld]);
        extension_type_map.insert("docx", vec![FileType::MsOfficeNew, FileType::Zip]);
        extension_type_map.insert("xlsx", vec![FileType::MsOfficeNew, FileType::Zip]);
        extension_type_map.insert("pptx", vec![FileType::MsOfficeNew, FileType::Zip]);
        extension_type_map.insert("rtf",  vec![FileType::Rtf]);

        // ── Risk scores ──
        let mut extension_risk_map: HashMap<&'static str, f32> =
            HashMap::new();

        // Critical risk
        let critical = ["exe","dll","scr","com","pif","vbs","bat","cmd","ps1"];
        for ext in critical { extension_risk_map.insert(ext, 1.0); }

        // High risk
        let high = ["sh","bash","php","jar","msi","apk","dmg","app","deb","rpm"];
        for ext in high { extension_risk_map.insert(ext, 0.8); }

        // Medium risk
        let medium = ["py","js","rb","pl","r","class","swf","pdf","doc","xls","ppt"];
        for ext in medium { extension_risk_map.insert(ext, 0.4); }

        // Low risk archives
        let archives = ["zip","rar","7z","gz","bz2","tar","xz"];
        for ext in archives { extension_risk_map.insert(ext, 0.2); }

        // Safe media
        let media = [
            "mp4","mkv","avi","mov","flv","wmv","webm",
            "mp3","flac","ogg","wav","aac","m4a",
            "png","jpg","jpeg","gif","bmp","webp","svg",
        ];
        for ext in media { extension_risk_map.insert(ext, 0.0); }

        Self {
            extension_type_map,
            extension_risk_map,
        }
    }

    // ─────────────────────────────────────
    // PUBLIC API
    // ─────────────────────────────────────

    /// Extract file extension from filename (lowercase, no dot)
    pub fn get_extension(filename: &str) -> String {
        std::path::Path::new(filename)
            .extension()
            .and_then(|ext| ext.to_str())
            .unwrap_or("")
            .to_lowercase()
    }

    /// Get risk score for a file extension [0.0, 1.0]
    pub fn get_risk_score(&self, extension: &str) -> f32 {
        *self.extension_risk_map
            .get(extension)
            .unwrap_or(&0.3) // Unknown extension = medium risk
    }

    /// Check if the extension matches the actual file type
    /// (extension spoofing detection)
    pub fn is_spoofed(
        &self,
        extension: &str,
        actual_type: &FileType,
    ) -> bool {
        // Unknown extension = can't detect spoofing
        if extension.is_empty() {
            return false;
        }

        // Get expected types for this extension
        let expected_types = match self.extension_type_map.get(extension) {
            Some(types) => types,
            None => return false, // Unknown extension - skip
        };

        // If actual type is unknown, can't determine spoofing
        if *actual_type == FileType::Unknown {
            return false;
        }

        // Special case: Office XML formats (.docx) are ZIP files internally
        if matches!(actual_type, FileType::Zip)
            && matches!(
                extension,
                "docx" | "xlsx" | "pptx" | "odt" | "ods" | "odp"
                    | "jar" | "apk" | "epub"
            )
        {
            return false;
        }

        // Check if actual type is in expected types
        !expected_types.contains(actual_type)
    }

    /// Check if this is a high-risk extension
    pub fn is_high_risk(&self, extension: &str) -> bool {
        self.get_risk_score(extension) >= 0.7
    }

    /// Check if this is an executable extension
    pub fn is_executable_extension(&self, extension: &str) -> bool {
        matches!(
            extension,
            "exe" | "dll" | "scr" | "com" | "pif"
                | "msi" | "bat" | "cmd" | "ps1" | "vbs"
                | "so"  | "dylib" | "app" | "dex" | "apk"
        )
    }

    /// Check if extension is known to Shadow Catcher
    pub fn is_known_extension(&self, extension: &str) -> bool {
        self.extension_type_map.contains_key(extension)
    }

    /// Get all high-risk extensions
    pub fn get_high_risk_extensions(&self) -> Vec<&str> {
        self.extension_risk_map
            .iter()
            .filter(|(_, &score)| score >= 0.7)
            .map(|(&ext, _)| ext)
            .collect()
    }

    /// Validate a download URL extension
    ///
    /// Returns (is_safe, risk_score, reason)
    pub fn validate_url(
        &self,
        url: &str,
    ) -> (bool, f32, String) {
        // Extract filename from URL
        let filename = url
            .split('?')
            .next()
            .unwrap_or(url)
            .split('/')
            .last()
            .unwrap_or("");

        let ext = Self::get_extension(filename);

        if ext.is_empty() {
            return (true, 0.1, "No extension detected".to_string());
        }

        let risk = self.get_risk_score(&ext);
        let is_safe = risk < 0.7;

        let reason = if is_safe {
            format!(".{} is considered safe (risk: {:.0}%)", ext, risk * 100.0)
        } else {
            format!(
                ".{} is HIGH RISK (risk: {:.0}%)",
                ext,
                risk * 100.0
            )
        };

        (is_safe, risk, reason)
    }
}

impl Default for ExtensionChecker {
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

    fn checker() -> ExtensionChecker {
        ExtensionChecker::new()
    }

    #[test]
    fn test_get_extension_png() {
        assert_eq!(
            ExtensionChecker::get_extension("photo.png"),
            "png"
        );
    }

    #[test]
    fn test_get_extension_uppercase() {
        assert_eq!(
            ExtensionChecker::get_extension("VIDEO.MP4"),
            "mp4"
        );
    }

    #[test]
    fn test_get_extension_no_ext() {
        assert_eq!(
            ExtensionChecker::get_extension("Makefile"),
            ""
        );
    }

    #[test]
    fn test_get_extension_multiple_dots() {
        assert_eq!(
            ExtensionChecker::get_extension("archive.tar.gz"),
            "gz"
        );
    }

    #[test]
    fn test_exe_is_high_risk() {
        assert!(checker().is_high_risk("exe"));
    }

    #[test]
    fn test_mp4_is_not_high_risk() {
        assert!(!checker().is_high_risk("mp4"));
    }

    #[test]
    fn test_png_is_not_executable() {
        assert!(!checker().is_executable_extension("png"));
    }

    #[test]
    fn test_exe_is_executable() {
        assert!(checker().is_executable_extension("exe"));
    }

    #[test]
    fn test_spoofing_detected_pe_as_png() {
        let c = checker();
        // File with .png extension but PE magic bytes
        assert!(c.is_spoofed("png", &FileType::PeExecutable));
    }

    #[test]
    fn test_no_spoofing_valid_png() {
        let c = checker();
        assert!(!c.is_spoofed("png", &FileType::Png));
    }

    #[test]
    fn test_docx_is_zip_not_spoofed() {
        let c = checker();
        // .docx files are internally ZIP - should NOT be flagged
        assert!(!c.is_spoofed("docx", &FileType::Zip));
    }

    #[test]
    fn test_risk_score_exe() {
        let score = checker().get_risk_score("exe");
        assert_eq!(score, 1.0);
    }

    #[test]
    fn test_risk_score_mp3() {
        let score = checker().get_risk_score("mp3");
        assert_eq!(score, 0.0);
    }

    #[test]
    fn test_validate_url_safe() {
        let (safe, _, _) = checker()
            .validate_url("https://example.com/video.mp4");
        assert!(safe);
    }

    #[test]
    fn test_validate_url_dangerous() {
        let (safe, risk, _) = checker()
            .validate_url("https://example.com/setup.exe");
        assert!(!safe);
        assert!(risk >= 0.7);
    }
}
