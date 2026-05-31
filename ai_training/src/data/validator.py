# ============================================
# SHADOW CATCHER - Data Validator
# ============================================
"""
Validates dataset integrity before training.

Checks:
  - CSV structure and required columns
  - Label distribution (no extreme imbalance)
  - Feature value ranges
  - Missing/NaN values
  - Duplicate samples
  - File path validity (for sample datasets)
  - Minimum dataset size requirements
"""

import os
import logging
from pathlib import Path
from typing import List, Optional, Tuple

import numpy as np
import pandas as pd

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────
# VALIDATION RESULT
# ─────────────────────────────────────────

class ValidationResult:
    """Holds the result of a validation check."""

    def __init__(self):
        self.passed = []
        self.warnings = []
        self.errors = []
        self.stats = {}

    @property
    def is_valid(self) -> bool:
        return len(self.errors) == 0

    def add_pass(self, check: str, detail: str = ""):
        self.passed.append(f"✓ {check}" + (f": {detail}" if detail else ""))

    def add_warning(self, check: str, detail: str = ""):
        self.warnings.append(f"⚠ {check}" + (f": {detail}" if detail else ""))
        logger.warning(f"[VALIDATION WARNING] {check}: {detail}")

    def add_error(self, check: str, detail: str = ""):
        self.errors.append(f"✗ {check}" + (f": {detail}" if detail else ""))
        logger.error(f"[VALIDATION ERROR] {check}: {detail}")

    def print_report(self):
        print("\n" + "=" * 60)
        print("DATASET VALIDATION REPORT")
        print("=" * 60)

        if self.passed:
            print(f"\n✅ PASSED ({len(self.passed)}):")
            for msg in self.passed:
                print(f"  {msg}")

        if self.warnings:
            print(f"\n⚠️  WARNINGS ({len(self.warnings)}):")
            for msg in self.warnings:
                print(f"  {msg}")

        if self.errors:
            print(f"\n❌ ERRORS ({len(self.errors)}):")
            for msg in self.errors:
                print(f"  {msg}")

        print(f"\n{'✅ VALID' if self.is_valid else '❌ INVALID'}")
        print("=" * 60)

        if self.stats:
            print("\nSTATISTICS:")
            for key, val in self.stats.items():
                print(f"  {key}: {val}")


# ─────────────────────────────────────────
# DATA VALIDATOR CLASS
# ─────────────────────────────────────────

class DataValidator:
    """
    Validates datasets before training to catch data issues early.

    Usage:
        validator = DataValidator()
        result = validator.validate_csv("datasets/combined/train_set.csv")
        if not result.is_valid:
            raise ValueError("Dataset validation failed")
    """

    # Required columns in CSV files
    REQUIRED_COLUMNS = ["label"]

    # Valid label values
    VALID_LABELS = {0, 1}

    # Minimum samples required
    MIN_SAMPLES = 100
    MIN_SAMPLES_PER_CLASS = 10

    # Maximum allowed imbalance ratio
    MAX_IMBALANCE_RATIO = 100.0

    # Feature value range
    FEATURE_MIN = 0.0
    FEATURE_MAX = 1.0

    # Maximum fraction of NaN values allowed
    MAX_NAN_FRACTION = 0.01

    def __init__(
        self,
        strict: bool = False,
        min_samples: int = 100,
    ):
        """
        Initialize validator.

        Args:
            strict: If True, warnings become errors
            min_samples: Minimum required samples in dataset
        """
        self.strict = strict
        self.MIN_SAMPLES = min_samples

    def validate_csv(self, csv_path: str) -> ValidationResult:
        """
        Validate a CSV dataset file.

        Args:
            csv_path: Path to CSV file

        Returns:
            ValidationResult with detailed check results
        """
        result = ValidationResult()

        logger.info(f"Validating: {csv_path}")

        # Check 1: File exists
        if not os.path.exists(csv_path):
            result.add_error("File exists", f"Not found: {csv_path}")
            result.print_report()
            return result

        result.add_pass("File exists", csv_path)

        # Check 2: File is not empty
        file_size = os.path.getsize(csv_path)
        if file_size == 0:
            result.add_error("File not empty", "File is 0 bytes")
            result.print_report()
            return result

        result.add_pass("File not empty", f"{file_size:,} bytes")

        # Load CSV
        try:
            df = pd.read_csv(csv_path)
            result.add_pass("CSV loads successfully", f"{len(df)} rows")
        except Exception as e:
            result.add_error("CSV loads successfully", str(e))
            result.print_report()
            return result

        # Run all checks on loaded DataFrame
        self._check_columns(df, result)
        self._check_size(df, result)
        self._check_labels(df, result)
        self._check_class_balance(df, result)
        self._check_missing_values(df, result)
        self._check_feature_ranges(df, result)
        self._check_duplicates(df, result)

        # Compute statistics
        result.stats = self._compute_stats(df)

        result.print_report()
        return result

    def validate_dataframe(
        self,
        df: pd.DataFrame,
        name: str = "DataFrame",
    ) -> ValidationResult:
        """Validate a pandas DataFrame directly."""
        result = ValidationResult()
        logger.info(f"Validating DataFrame: {name}")

        self._check_columns(df, result)
        self._check_size(df, result)
        self._check_labels(df, result)
        self._check_class_balance(df, result)
        self._check_missing_values(df, result)
        self._check_feature_ranges(df, result)
        self._check_duplicates(df, result)

        result.stats = self._compute_stats(df)
        return result

    def validate_numpy(
        self,
        X: np.ndarray,
        y: np.ndarray,
    ) -> ValidationResult:
        """Validate numpy arrays."""
        result = ValidationResult()

        # Shape check
        if len(X) != len(y):
            result.add_error(
                "Shape mismatch",
                f"X has {len(X)} samples, y has {len(y)} labels"
            )
        else:
            result.add_pass("Shape match", f"{len(X)} samples")

        # NaN check
        if np.any(np.isnan(X)):
            result.add_error("No NaN in features", "NaN values found in X")
        else:
            result.add_pass("No NaN in features")

        # Inf check
        if np.any(np.isinf(X)):
            result.add_error("No Inf in features", "Inf values found in X")
        else:
            result.add_pass("No Inf in features")

        # Label check
        unique_labels = set(y.tolist())
        invalid = unique_labels - self.VALID_LABELS
        if invalid:
            result.add_error("Valid labels", f"Invalid labels found: {invalid}")
        else:
            result.add_pass("Valid labels", f"Labels: {unique_labels}")

        # Size check
        if len(X) < self.MIN_SAMPLES:
            result.add_error(
                "Minimum samples",
                f"Need {self.MIN_SAMPLES}, got {len(X)}"
            )
        else:
            result.add_pass("Minimum samples", f"{len(X)} samples")

        return result

    def _check_columns(self, df: pd.DataFrame, result: ValidationResult):
        """Check required columns exist."""
        for col in self.REQUIRED_COLUMNS:
            if col in df.columns:
                result.add_pass(f"Column '{col}' exists")
            else:
                result.add_error(
                    f"Column '{col}' exists",
                    f"Available: {list(df.columns)}"
                )

    def _check_size(self, df: pd.DataFrame, result: ValidationResult):
        """Check dataset has enough samples."""
        n = len(df)
        if n >= self.MIN_SAMPLES:
            result.add_pass("Minimum samples", f"{n} samples")
        else:
            result.add_error(
                "Minimum samples",
                f"Need {self.MIN_SAMPLES}, got {n}"
            )

    def _check_labels(self, df: pd.DataFrame, result: ValidationResult):
        """Check label values are valid."""
        if "label" not in df.columns:
            return

        unique = set(df["label"].unique().tolist())
        invalid = unique - self.VALID_LABELS

        if invalid:
            result.add_error(
                "Valid label values",
                f"Invalid labels: {invalid}. Expected: {self.VALID_LABELS}"
            )
        else:
            result.add_pass("Valid label values", f"Found: {unique}")

    def _check_class_balance(self, df: pd.DataFrame, result: ValidationResult):
        """Check class distribution is not too imbalanced."""
        if "label" not in df.columns:
            return

        counts = df["label"].value_counts()

        # Check minimum per class
        for label, count in counts.items():
            if count < self.MIN_SAMPLES_PER_CLASS:
                result.add_error(
                    f"Minimum samples for class {label}",
                    f"Got {count}, need {self.MIN_SAMPLES_PER_CLASS}"
                )
            else:
                result.add_pass(
                    f"Class {label} sample count",
                    f"{count} samples"
                )

        # Check imbalance ratio
        if len(counts) >= 2:
            ratio = counts.max() / counts.min()
            if ratio > self.MAX_IMBALANCE_RATIO:
                result.add_warning(
                    "Class imbalance",
                    f"Ratio: {ratio:.1f}:1 (threshold: {self.MAX_IMBALANCE_RATIO}:1)"
                )
            else:
                result.add_pass("Class balance", f"Ratio: {ratio:.1f}:1")

    def _check_missing_values(
        self,
        df: pd.DataFrame,
        result: ValidationResult,
    ):
        """Check for missing/NaN values."""
        total_cells = df.shape[0] * df.shape[1]
        nan_count = df.isnull().sum().sum()
        nan_fraction = nan_count / total_cells if total_cells > 0 else 0

        if nan_fraction > self.MAX_NAN_FRACTION:
            result.add_error(
                "Missing values",
                f"{nan_count} NaN values ({nan_fraction:.2%} of data)"
            )
        elif nan_count > 0:
            result.add_warning(
                "Missing values",
                f"{nan_count} NaN values ({nan_fraction:.2%} of data)"
            )
        else:
            result.add_pass("No missing values")

    def _check_feature_ranges(
        self,
        df: pd.DataFrame,
        result: ValidationResult,
    ):
        """Check feature values are within expected range."""
        feature_cols = [c for c in df.columns if c.startswith("f_")]

        if not feature_cols:
            result.add_warning(
                "Feature columns",
                "No columns starting with 'f_' found"
            )
            return

        feature_data = df[feature_cols].values

        min_val = float(np.nanmin(feature_data))
        max_val = float(np.nanmax(feature_data))

        if min_val < self.FEATURE_MIN - 0.01:
            result.add_warning(
                "Feature range minimum",
                f"Min value {min_val:.4f} below expected {self.FEATURE_MIN}"
            )
        else:
            result.add_pass("Feature range minimum", f"Min: {min_val:.4f}")

        if max_val > self.FEATURE_MAX + 0.01:
            result.add_warning(
                "Feature range maximum",
                f"Max value {max_val:.4f} above expected {self.FEATURE_MAX}"
            )
        else:
            result.add_pass("Feature range maximum", f"Max: {max_val:.4f}")

    def _check_duplicates(self, df: pd.DataFrame, result: ValidationResult):
        """Check for duplicate rows."""
        n_duplicates = df.duplicated().sum()

        if n_duplicates > 0:
            dup_fraction = n_duplicates / len(df)
            if dup_fraction > 0.1:
                result.add_warning(
                    "Duplicate rows",
                    f"{n_duplicates} duplicates ({dup_fraction:.1%})"
                )
            else:
                result.add_warning(
                    "Duplicate rows",
                    f"{n_duplicates} duplicates"
                )
        else:
            result.add_pass("No duplicate rows")

    def _compute_stats(self, df: pd.DataFrame) -> dict:
        """Compute dataset statistics."""
        stats = {
            "total_samples": len(df),
            "total_columns": len(df.columns),
        }

        if "label" in df.columns:
            counts = df["label"].value_counts().to_dict()
            stats["benign_count"] = counts.get(0, 0)
            stats["malicious_count"] = counts.get(1, 0)
            if counts.get(0, 0) > 0:
                stats["imbalance_ratio"] = round(
                    counts.get(1, 0) / counts.get(0, 1), 3
                )

        feature_cols = [c for c in df.columns if c.startswith("f_")]
        stats["feature_count"] = len(feature_cols)

        return stats

    def validate_all_splits(
        self,
        train_path: str,
        val_path: str,
        test_path: str,
    ) -> bool:
        """
        Validate all three dataset splits.

        Returns:
            True if all splits are valid
        """
        print("\n" + "=" * 60)
        print("VALIDATING ALL DATASET SPLITS")
        print("=" * 60)

        all_valid = True

        for name, path in [
            ("TRAIN", train_path),
            ("VALIDATION", val_path),
            ("TEST", test_path),
        ]:
            print(f"\n[{name}] {path}")
            result = self.validate_csv(path)
            if not result.is_valid:
                all_valid = False
                logger.error(f"{name} split validation failed")

        print("\n" + "=" * 60)
        print(f"OVERALL: {'✅ ALL VALID' if all_valid else '❌ VALIDATION FAILED'}")
        print("=" * 60)

        return all_valid
