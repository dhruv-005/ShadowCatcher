# ============================================
# SHADOW CATCHER - Feature Extractor
# ============================================
"""
Extracts features from binary files for malware classification.

Features extracted:
  - Raw header bytes (first 512 bytes)
  - Magic byte signature
  - Byte frequency histogram
  - Shannon entropy
  - File metadata features
  - Section header features (PE files)
  - String density
"""

import os
import math
import struct
import hashlib
import logging
from pathlib import Path
from typing import Optional

import numpy as np

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────
# MAGIC BYTE SIGNATURES
# ─────────────────────────────────────────

MAGIC_SIGNATURES = {
    # Executables
    b"\x4D\x5A": "PE_EXE",           # Windows PE
    b"\x7FELF": "ELF",               # Linux ELF
    b"\xCE\xFA\xED\xFE": "MACHO32",  # macOS 32-bit
    b"\xCF\xFA\xED\xFE": "MACHO64",  # macOS 64-bit

    # Archives
    b"\x50\x4B\x03\x04": "ZIP",      # ZIP/APK/JAR/DOCX
    b"\x52\x61\x72\x21": "RAR",      # RAR
    b"\x1F\x8B": "GZIP",             # GZIP
    b"\x42\x5A\x68": "BZIP2",        # BZIP2
    b"\xFD\x37\x7A\x58": "XZ",       # XZ

    # Documents
    b"\x25\x50\x44\x46": "PDF",      # PDF
    b"\xD0\xCF\x11\xE0": "OLE",      # MS Office (old)

    # Images
    b"\x89\x50\x4E\x47": "PNG",      # PNG
    b"\xFF\xD8\xFF": "JPEG",         # JPEG
    b"\x47\x49\x46\x38": "GIF",      # GIF
    b"\x42\x4D": "BMP",              # BMP

    # Media
    b"\x00\x00\x00\x20\x66\x74\x79\x70": "MP4",  # MP4
    b"\x49\x44\x33": "MP3",          # MP3
    b"\x52\x49\x46\x46": "WAV",      # WAV/AVI

    # Scripts
    b"\x23\x21": "SHEBANG",          # Shell script
    b"\xEF\xBB\xBF": "UTF8_BOM",     # UTF-8 BOM (often scripts)
}


# ─────────────────────────────────────────
# FEATURE EXTRACTOR CLASS
# ─────────────────────────────────────────

class FeatureExtractor:
    """
    Extract features from binary files for ML classification.

    Usage:
        extractor = FeatureExtractor(header_size=512)
        features = extractor.extract_from_file("sample.exe")
        # features shape: (512,) numpy array
    """

    def __init__(
        self,
        header_size: int = 512,
        normalize: bool = True,
        include_entropy: bool = True,
        include_histogram: bool = True,
        include_metadata: bool = True,
    ):
        """
        Initialize the feature extractor.

        Args:
            header_size: Number of bytes to read from file start
            normalize: Normalize byte values to [0, 1]
            include_entropy: Include Shannon entropy features
            include_histogram: Include byte frequency histogram
            include_metadata: Include file metadata features
        """
        self.header_size = header_size
        self.normalize = normalize
        self.include_entropy = include_entropy
        self.include_histogram = include_histogram
        self.include_metadata = include_metadata

        logger.debug(
            f"FeatureExtractor initialized: "
            f"header_size={header_size}, "
            f"normalize={normalize}"
        )

    def extract_from_file(
        self,
        file_path: str,
    ) -> Optional[np.ndarray]:
        """
        Extract features from a file on disk.

        Args:
            file_path: Path to the file

        Returns:
            Feature vector as numpy array, or None on error
        """
        try:
            path = Path(file_path)

            if not path.exists():
                logger.error(f"File not found: {file_path}")
                return None

            if not path.is_file():
                logger.error(f"Not a file: {file_path}")
                return None

            file_size = path.stat().st_size
            if file_size == 0:
                logger.warning(f"Empty file: {file_path}")
                return self._empty_features()

            with open(path, "rb") as f:
                raw_bytes = f.read(self.header_size)

            return self.extract_from_bytes(raw_bytes, file_size)

        except PermissionError:
            logger.error(f"Permission denied: {file_path}")
            return None
        except Exception as e:
            logger.error(f"Error extracting features from {file_path}: {e}")
            return None

    def extract_from_bytes(
        self,
        raw_bytes: bytes,
        file_size: int = 0,
    ) -> np.ndarray:
        """
        Extract features directly from raw bytes.

        Args:
            raw_bytes: Raw file bytes (first N bytes)
            file_size: Total file size in bytes

        Returns:
            Feature vector as numpy array of shape (header_size,)
        """
        # Pad or truncate to header_size
        byte_array = self._pad_bytes(raw_bytes)

        # Base feature: raw bytes normalized to [0, 1]
        features = byte_array.astype(np.float32)

        if self.normalize:
            features = features / 255.0

        return features

    def extract_full_features(
        self,
        raw_bytes: bytes,
        file_size: int = 0,
        file_extension: str = "",
    ) -> np.ndarray:
        """
        Extract comprehensive feature set including entropy,
        histogram, and metadata.

        Returns:
            Extended feature vector
        """
        byte_array = self._pad_bytes(raw_bytes)

        feature_parts = []

        # 1. Raw bytes (normalized)
        raw_features = byte_array.astype(np.float32) / 255.0
        feature_parts.append(raw_features)

        # 2. Shannon entropy of different windows
        if self.include_entropy:
            entropy_features = self._compute_entropy_features(byte_array)
            feature_parts.append(entropy_features)

        # 3. Byte frequency histogram (256 bins)
        if self.include_histogram:
            histogram = self._compute_histogram(byte_array)
            feature_parts.append(histogram)

        # 4. File metadata features
        if self.include_metadata:
            metadata = self._compute_metadata_features(
                raw_bytes, file_size, file_extension
            )
            feature_parts.append(metadata)

        return np.concatenate(feature_parts).astype(np.float32)

    def _pad_bytes(self, raw_bytes: bytes) -> np.ndarray:
        """Pad or truncate bytes to header_size."""
        byte_array = np.frombuffer(raw_bytes, dtype=np.uint8).copy()

        if len(byte_array) < self.header_size:
            # Pad with zeros
            padded = np.zeros(self.header_size, dtype=np.uint8)
            padded[:len(byte_array)] = byte_array
            return padded
        else:
            return byte_array[:self.header_size]

    def _compute_entropy_features(
        self,
        byte_array: np.ndarray,
        num_windows: int = 4,
    ) -> np.ndarray:
        """
        Compute Shannon entropy over sliding windows.

        High entropy → likely encrypted/compressed/packed
        Low entropy  → likely plaintext/structured data
        """
        entropies = []
        window_size = len(byte_array) // num_windows

        for i in range(num_windows):
            start = i * window_size
            end = start + window_size
            window = byte_array[start:end]
            entropy = self._shannon_entropy(window)
            entropies.append(entropy / 8.0)  # Normalize to [0, 1]

        # Overall entropy
        overall = self._shannon_entropy(byte_array)
        entropies.append(overall / 8.0)

        return np.array(entropies, dtype=np.float32)

    def _shannon_entropy(self, data: np.ndarray) -> float:
        """Compute Shannon entropy of byte array."""
        if len(data) == 0:
            return 0.0

        # Count byte frequencies
        counts = np.bincount(data, minlength=256)
        probs = counts / len(data)

        # Remove zero probabilities
        probs = probs[probs > 0]

        # Compute entropy
        entropy = -np.sum(probs * np.log2(probs))
        return float(entropy)

    def _compute_histogram(
        self,
        byte_array: np.ndarray,
    ) -> np.ndarray:
        """
        Compute normalized byte frequency histogram (256 bins).
        Shows distribution of byte values.
        """
        hist = np.bincount(byte_array, minlength=256).astype(np.float32)
        total = len(byte_array)
        if total > 0:
            hist = hist / total  # Normalize to [0, 1]
        return hist

    def _compute_metadata_features(
        self,
        raw_bytes: bytes,
        file_size: int,
        file_extension: str,
    ) -> np.ndarray:
        """
        Compute file metadata features.

        Features:
          - File size (log-normalized)
          - Magic byte type (one-hot encoded)
          - Has valid PE header
          - Has valid ELF header
          - Extension matches magic bytes
          - Printable string density
        """
        features = []

        # File size (log scale, normalized)
        if file_size > 0:
            log_size = math.log10(file_size) / 10.0
        else:
            log_size = 0.0
        features.append(min(log_size, 1.0))

        # Magic byte detection
        detected_magic = self._detect_magic(raw_bytes)
        features.append(1.0 if detected_magic == "PE_EXE" else 0.0)
        features.append(1.0 if detected_magic == "ELF" else 0.0)
        features.append(1.0 if detected_magic == "ZIP" else 0.0)
        features.append(1.0 if detected_magic == "PDF" else 0.0)
        features.append(1.0 if detected_magic == "UNKNOWN" else 0.0)

        # PE header features
        is_pe = raw_bytes[:2] == b"\x4D\x5A"
        features.append(1.0 if is_pe else 0.0)

        # ELF header features
        is_elf = raw_bytes[:4] == b"\x7FELF"
        features.append(1.0 if is_elf else 0.0)

        # Extension mismatch (common malware indicator)
        ext_mismatch = self._check_extension_mismatch(
            detected_magic, file_extension
        )
        features.append(1.0 if ext_mismatch else 0.0)

        # Printable string density
        byte_array = np.frombuffer(raw_bytes, dtype=np.uint8)
        printable = np.sum(
            (byte_array >= 32) & (byte_array <= 126)
        ) / max(len(byte_array), 1)
        features.append(float(printable))

        # Null byte density (high in many malware)
        null_density = np.sum(byte_array == 0) / max(len(byte_array), 1)
        features.append(float(null_density))

        return np.array(features, dtype=np.float32)

    def _detect_magic(self, raw_bytes: bytes) -> str:
        """Detect file type from magic bytes."""
        for signature, file_type in MAGIC_SIGNATURES.items():
            if raw_bytes[:len(signature)] == signature:
                return file_type
        return "UNKNOWN"

    def _check_extension_mismatch(
        self,
        detected_magic: str,
        file_extension: str,
    ) -> bool:
        """
        Check if file extension matches detected magic bytes.
        Extension mismatch is a strong malware indicator.
        """
        extension_map = {
            "PE_EXE": [".exe", ".dll", ".sys", ".com"],
            "ELF": [".elf", ".so", ".out", ""],
            "PDF": [".pdf"],
            "ZIP": [".zip", ".apk", ".jar", ".docx", ".xlsx"],
            "PNG": [".png"],
            "JPEG": [".jpg", ".jpeg"],
            "MP4": [".mp4", ".m4v"],
            "MP3": [".mp3"],
        }

        ext = file_extension.lower()
        expected_exts = extension_map.get(detected_magic, [])

        if not expected_exts:
            return False  # Unknown type, can't determine mismatch

        return ext not in expected_exts

    def _empty_features(self) -> np.ndarray:
        """Return zero features for empty files."""
        return np.zeros(self.header_size, dtype=np.float32)

    def get_feature_size(self) -> int:
        """Get total feature vector size."""
        size = self.header_size
        if self.include_entropy:
            size += 5   # 4 windows + overall
        if self.include_histogram:
            size += 256
        if self.include_metadata:
            size += 11
        return size

    def compute_file_hash(self, file_path: str) -> dict:
        """
        Compute MD5 and SHA256 hashes of a file.
        Used for known malware hash database lookup.
        """
        md5 = hashlib.md5()
        sha256 = hashlib.sha256()

        try:
            with open(file_path, "rb") as f:
                while chunk := f.read(8192):
                    md5.update(chunk)
                    sha256.update(chunk)

            return {
                "md5": md5.hexdigest(),
                "sha256": sha256.hexdigest(),
            }
        except Exception as e:
            logger.error(f"Hash computation failed: {e}")
            return {"md5": "", "sha256": ""}
