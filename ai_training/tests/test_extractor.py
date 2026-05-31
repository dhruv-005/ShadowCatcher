# ============================================
# SHADOW CATCHER - Feature Extractor Tests
# ============================================

import sys
import os
import pytest
import numpy as np
import tempfile
from pathlib import Path

sys.path.append(str(Path(__file__).parent.parent / "src"))

from data.extractor import FeatureExtractor, FEATURE_SIZE


# ─────────────────────────────────────────
# FIXTURES
# ─────────────────────────────────────────

@pytest.fixture
def extractor():
    """Create a FeatureExtractor instance."""
    return FeatureExtractor(feature_size=FEATURE_SIZE)


@pytest.fixture
def benign_png_bytes():
    """Minimal valid PNG file bytes."""
    return (
        b"\x89PNG\r\n\x1a\n"          # PNG magic
        b"\x00\x00\x00\rIHDR"          # IHDR chunk
        b"\x00\x00\x00\x01"            # width: 1
        b"\x00\x00\x00\x01"            # height: 1
        b"\x08\x02"                    # bit depth, color type
        b"\x00\x00\x00"                # compression, filter, interlace
        b"\x90wS\xde"                  # CRC
        + b"\x00" * 200                # padding
    )


@pytest.fixture
def malicious_pe_bytes():
    """Fake PE executable header bytes."""
    return (
        b"MZ"                          # PE magic
        b"\x90\x00\x03\x00\x00\x00"   # PE header start
        b"\x04\x00\x00\x00\xff\xff"
        b"This program cannot be run in DOS mode\r\n\r\n"
        b"\x00" * 200
    )


@pytest.fixture
def temp_png_file(benign_png_bytes):
    """Create a temporary PNG file."""
    with tempfile.NamedTemporaryFile(
        suffix=".png",
        delete=False
    ) as f:
        f.write(benign_png_bytes)
        temp_path = f.name
    yield temp_path
    os.unlink(temp_path)


@pytest.fixture
def temp_exe_file(malicious_pe_bytes):
    """Create a temporary EXE file."""
    with tempfile.NamedTemporaryFile(
        suffix=".exe",
        delete=False
    ) as f:
        f.write(malicious_pe_bytes)
        temp_path = f.name
    yield temp_path
    os.unlink(temp_path)


@pytest.fixture
def temp_fake_png_file(malicious_pe_bytes):
    """Create a fake PNG (actually PE) file - extension spoofing."""
    with tempfile.NamedTemporaryFile(
        suffix=".png",
        delete=False
    ) as f:
        f.write(malicious_pe_bytes)
        temp_path = f.name
    yield temp_path
    os.unlink(temp_path)


# ─────────────────────────────────────────
# FEATURE VECTOR TESTS
# ─────────────────────────────────────────

class TestFeatureVectorShape:
    """Test that feature vectors have correct shape."""

    def test_extract_from_bytes_returns_correct_shape(self, extractor):
        """Feature vector must be exactly FEATURE_SIZE."""
        data = b"\x89PNG" + b"\x00" * 508
        features = extractor.extract_from_bytes(data)
        assert features.shape == (FEATURE_SIZE,), (
            f"Expected shape ({FEATURE_SIZE},), got {features.shape}"
        )

    def test_extract_from_file_returns_correct_shape(
        self, extractor, temp_png_file
    ):
        """File extraction must return correct shape."""
        features = extractor.extract_from_file(temp_png_file)
        assert features is not None
        assert features.shape == (FEATURE_SIZE,)

    def test_empty_bytes_returns_zeros(self, extractor):
        """Empty input should return zero vector."""
        features = extractor.extract_from_bytes(b"")
        assert features.shape == (FEATURE_SIZE,)
        assert np.all(features == 0.0)

    def test_single_byte_input(self, extractor):
        """Single byte input should not crash."""
        features = extractor.extract_from_bytes(b"\xff")
        assert features.shape == (FEATURE_SIZE,)

    def test_large_file_bytes(self, extractor):
        """Large file should only read first N bytes."""
        data = b"\x89PNG" + b"\xaa" * 100000
        features = extractor.extract_from_bytes(data)
        assert features.shape == (FEATURE_SIZE,)

    def test_batch_extraction_shape(self, extractor, tmp_path):
        """Batch extraction returns correct shape."""
        files = []
        for i in range(5):
            p = tmp_path / f"test_{i}.bin"
            p.write_bytes(b"\x89PNG" + b"\x00" * 200)
            files.append(str(p))

        features, success = extractor.extract_batch(files)
        assert features.shape == (5, FEATURE_SIZE)
        assert len(success) == 5


# ─────────────────────────────────────────
# FEATURE VALUE TESTS
# ─────────────────────────────────────────

class TestFeatureValues:
    """Test that feature values are in valid ranges."""

    def test_features_in_valid_range(self, extractor):
        """All feature values must be in [0, 1]."""
        data = b"\x89PNG" + b"\xab\xcd\xef" * 100
        features = extractor.extract_from_bytes(data)
        assert np.all(features >= 0.0), "Features below 0.0"
        assert np.all(features <= 1.0), "Features above 1.0"

    def test_no_nan_values(self, extractor):
        """No NaN values in output."""
        data = b"\xff" * 512
        features = extractor.extract_from_bytes(data)
        assert not np.any(np.isnan(features)), "NaN found in features"

    def test_no_inf_values(self, extractor):
        """No Inf values in output."""
        data = b"\x00" * 512
        features = extractor.extract_from_bytes(data)
        assert not np.any(np.isinf(features)), "Inf found in features"

    def test_dtype_is_float32(self, extractor):
        """Feature vector must be float32."""
        data = b"\x89PNG" + b"\x00" * 200
        features = extractor.extract_from_bytes(data)
        assert features.dtype == np.float32, (
            f"Expected float32, got {features.dtype}"
        )

    def test_header_bytes_normalized(self, extractor):
        """Header bytes segment [0:256] should be in [0, 1]."""
        data = bytes(range(256))
        features = extractor.extract_from_bytes(data)
        header_segment = features[0:256]
        assert np.all(header_segment >= 0.0)
        assert np.all(header_segment <= 1.0)


# ─────────────────────────────────────────
# MAGIC BYTES DETECTION TESTS
# ─────────────────────────────────────────

class TestMagicBytesDetection:
    """Test magic byte detection accuracy."""

    def test_detects_png(self, extractor):
        """PNG magic bytes correctly identified."""
        data = b"\x89PNG\r\n\x1a\n" + b"\x00" * 200
        features = extractor.extract_from_bytes(data, "test.png")
        # features[264:280] = magic type one-hot
        magic_segment = features[264:280]
        assert magic_segment.sum() > 0, "No magic type detected"
        # PNG is index 9 (image category)
        assert magic_segment[9] == 1.0, "PNG not detected as image"

    def test_detects_pe_executable(self, extractor, malicious_pe_bytes):
        """PE executable (MZ header) correctly identified."""
        features = extractor.extract_from_bytes(
            malicious_pe_bytes, "malware.exe"
        )
        magic_segment = features[264:280]
        # PE is index 0
        assert magic_segment[0] == 1.0, "PE not detected as executable"

    def test_detects_elf(self, extractor):
        """ELF executable correctly identified."""
        data = b"\x7fELF" + b"\x00" * 200
        features = extractor.extract_from_bytes(data, "binary")
        magic_segment = features[264:280]
        # ELF is index 1
        assert magic_segment[1] == 1.0, "ELF not detected"

    def test_detects_zip(self, extractor):
        """ZIP archive correctly identified."""
        data = b"PK\x03\x04" + b"\x00" * 200
        features = extractor.extract_from_bytes(data, "archive.zip")
        magic_segment = features[264:280]
        # Archive is index 8
        assert magic_segment[8] == 1.0, "ZIP not detected"

    def test_unknown_type_fallback(self, extractor):
        """Unknown file type defaults to unknown category."""
        data = b"\x42\x43\x44\x45" + b"\x00" * 200
        features = extractor.extract_from_bytes(data, "unknown.xyz")
        magic_segment = features[264:280]
        # Unknown is index 15
        assert magic_segment[15] == 1.0, "Unknown type not detected"


# ─────────────────────────────────────────
# STRUCTURAL FEATURE TESTS
# ─────────────────────────────────────────

class TestStructuralFeatures:
    """Test structural feature extraction."""

    def test_extension_mismatch_detected(
        self, extractor, temp_fake_png_file
    ):
        """PE file with .png extension triggers mismatch flag."""
        features = extractor.extract_from_file(temp_fake_png_file)
        assert features is not None
        # features[283] = magic_ext_mismatch flag
        assert features[283] == 1.0, (
            "Extension mismatch not detected for fake PNG"
        )

    def test_no_mismatch_for_valid_png(self, extractor, temp_png_file):
        """Valid PNG with .png extension has no mismatch."""
        features = extractor.extract_from_file(temp_png_file)
        assert features is not None
        # For a valid PNG, mismatch should be 0
        assert features[283] == 0.0, (
            "False mismatch detected for valid PNG"
        )

    def test_pe_string_detected(self, extractor, malicious_pe_bytes):
        """'This program cannot be run' string detected."""
        features = extractor.extract_from_bytes(
            malicious_pe_bytes, "malware.exe"
        )
        # features[287] = has_pe_string
        assert features[287] == 1.0, "PE string not detected"

    def test_file_size_feature(self, extractor, tmp_path):
        """File size feature is non-zero for non-empty files."""
        p = tmp_path / "test.bin"
        p.write_bytes(b"\x89PNG" + b"\x00" * 1000)
        features = extractor.extract_from_file(str(p))
        # features[280] = file_size_log
        assert features[280] > 0.0, "File size feature is zero"

    def test_nonexistent_file_returns_none(self, extractor):
        """Non-existent file returns None."""
        features = extractor.extract_from_file("/nonexistent/path/file.exe")
        assert features is None


# ─────────────────────────────────────────
# ENTROPY TESTS
# ─────────────────────────────────────────

class TestEntropyFeatures:
    """Test entropy-based feature extraction."""

    def test_high_entropy_random_data(self, extractor):
        """Random data should have high entropy."""
        np.random.seed(42)
        data = bytes(np.random.randint(0, 256, 512).astype(np.uint8))
        features = extractor.extract_from_bytes(data)
        # features[256] = overall entropy (normalized)
        entropy = features[256]
        assert entropy > 0.8, (
            f"Random data should have high entropy, got {entropy}"
        )

    def test_low_entropy_repeated_data(self, extractor):
        """Repeated bytes should have low entropy."""
        data = b"\x41" * 512  # All 'A' characters
        features = extractor.extract_from_bytes(data)
        entropy = features[256]
        assert entropy < 0.1, (
            f"Repeated bytes should have low entropy, got {entropy}"
        )

    def test_null_bytes_ratio(self, extractor):
        """Null byte ratio correctly computed."""
        data = b"\x00" * 128 + b"\xff" * 128
        features = extractor.extract_from_bytes(data)
        # features[258] = null_ratio
        null_ratio = features[258]
        assert 0.4 < null_ratio < 0.6, (
            f"Expected ~0.5 null ratio, got {null_ratio}"
        )

    def test_printable_ratio(self, extractor):
        """Printable character ratio correctly computed."""
        data = b"Hello World! " * 40  # All printable ASCII
        features = extractor.extract_from_bytes(data)
        # features[261] = printable_ratio
        printable = features[261]  # Wait: index 261 in entropy segment
        assert printable > 0.8, (
            f"All-printable data should have high ratio, got {printable}"
        )


# ─────────────────────────────────────────
# STATISTICAL FEATURE TESTS
# ─────────────────────────────────────────

class TestStatisticalFeatures:
    """Test statistical feature extraction."""

    def test_byte_mean_feature(self, extractor):
        """Byte mean feature is correctly normalized."""
        data = bytes([128] * 512)  # Mean = 128
        features = extractor.extract_from_bytes(data)
        # features[200] = byte_mean (normalized to [0,1])
        mean_feat = features[296 + 200]
        expected = 128.0 / 255.0
        assert abs(mean_feat - expected) < 0.05, (
            f"Expected mean ~{expected:.3f}, got {mean_feat:.3f}"
        )

    def test_all_zeros_statistical(self, extractor):
        """All-zero data produces valid statistical features."""
        data = b"\x00" * 512
        features = extractor.extract_from_bytes(data)
        stat_segment = features[296:512]
        assert not np.any(np.isnan(stat_segment))
        assert not np.any(np.isinf(stat_segment))

    def test_all_max_bytes(self, extractor):
        """All 0xFF bytes produces valid features."""
        data = b"\xff" * 512
        features = extractor.extract_from_bytes(data)
        assert not np.any(np.isnan(features))
        assert not np.any(np.isinf(features))


# ─────────────────────────────────────────
# FEATURE NAMES TESTS
# ─────────────────────────────────────────

class TestFeatureNames:
    """Test feature name generation."""

    def test_feature_names_count(self, extractor):
        """Feature names count matches feature size."""
        names = extractor.get_feature_names()
        assert len(names) == FEATURE_SIZE, (
            f"Expected {FEATURE_SIZE} names, got {len(names)}"
        )

    def test_feature_names_unique(self, extractor):
        """All feature names are unique."""
        names = extractor.get_feature_names()
        assert len(names) == len(set(names)), (
            "Duplicate feature names found"
        )

    def test_feature_names_are_strings(self, extractor):
        """All feature names are strings."""
        names = extractor.get_feature_names()
        for name in names:
            assert isinstance(name, str), f"Non-string name: {name}"


# ─────────────────────────────────────────
# CONSISTENCY TESTS
# ─────────────────────────────────────────

class TestConsistency:
    """Test extraction consistency and determinism."""

    def test_same_input_same_output(self, extractor):
        """Same input always produces same output."""
        data = b"\x89PNG" + b"\xab" * 400
        features1 = extractor.extract_from_bytes(data)
        features2 = extractor.extract_from_bytes(data)
        np.testing.assert_array_equal(
            features1, features2,
            err_msg="Extraction is not deterministic"
        )

    def test_different_files_different_features(self, extractor):
        """Different files produce different feature vectors."""
        png_data = b"\x89PNG" + b"\x00" * 400
        exe_data = b"MZ\x90\x00" + b"\x00" * 400
        features_png = extractor.extract_from_bytes(png_data, "file.png")
        features_exe = extractor.extract_from_bytes(exe_data, "file.exe")
        assert not np.array_equal(features_png, features_exe), (
            "PNG and EXE should produce different features"
        )

    def test_file_and_bytes_match(self, extractor, temp_png_file):
        """extract_from_file and extract_from_bytes give same result."""
        with open(temp_png_file, "rb") as f:
            data = f.read()

        features_file = extractor.extract_from_file(temp_png_file)
        features_bytes = extractor.extract_from_bytes(
            data, os.path.basename(temp_png_file)
        )

        assert features_file is not None
        np.testing.assert_array_almost_equal(
            features_file,
            features_bytes,
            decimal=5,
            err_msg="File and bytes extraction mismatch"
        )


# ─────────────────────────────────────────
# PERFORMANCE TESTS
# ─────────────────────────────────────────

class TestPerformance:
    """Test extraction performance."""

    def test_extraction_speed(self, extractor):
        """Single file extraction should complete in < 10ms."""
        import time
        data = b"\x89PNG" + b"\xab" * 500

        # Warmup
        for _ in range(5):
            extractor.extract_from_bytes(data)

        # Benchmark
        start = time.perf_counter()
        for _ in range(100):
            extractor.extract_from_bytes(data)
        elapsed = (time.perf_counter() - start) * 1000 / 100

        assert elapsed < 10.0, (
            f"Extraction too slow: {elapsed:.2f}ms per sample"
        )

    def test_batch_extraction_100_files(self, extractor, tmp_path):
        """Batch extraction of 100 files completes in < 2 seconds."""
        import time

        files = []
        for i in range(100):
            p = tmp_path / f"sample_{i}.bin"
            p.write_bytes(b"\x89PNG" + bytes([i % 256]) * 300)
            files.append(str(p))

        start = time.perf_counter()
        features, success = extractor.extract_batch(files)
        elapsed = time.perf_counter() - start

        assert elapsed < 2.0, (
            f"Batch extraction too slow: {elapsed:.2f}s for 100 files"
        )
        assert features.shape == (100, FEATURE_SIZE)
