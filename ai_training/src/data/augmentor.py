# ============================================
# SHADOW CATCHER - Data Augmentor
# ============================================
"""
Augments the training dataset to improve model robustness.

Augmentation techniques:
  - Byte noise injection
  - Byte shuffling (partial)
  - Padding variation
  - Header truncation
  - Byte substitution
  - Class balancing via oversampling
"""

import logging
import random
from typing import List, Tuple, Optional

import numpy as np
import pandas as pd
from tqdm import tqdm

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────
# AUGMENTOR CLASS
# ─────────────────────────────────────────

class DataAugmentor:
    """
    Augment malware/benign dataset to improve model generalization.

    Handles:
    - Class imbalance (malware samples are rare)
    - Feature-space augmentation
    - Noise injection for robustness
    """

    def __init__(
        self,
        noise_level: float = 0.05,
        augmentation_factor: int = 3,
        random_seed: int = 42,
        balance_classes: bool = True,
    ):
        """
        Initialize augmentor.

        Args:
            noise_level: Fraction of bytes to add noise to (0.0-1.0)
            augmentation_factor: How many augmented copies per original
            random_seed: Random seed for reproducibility
            balance_classes: Whether to balance class distribution
        """
        self.noise_level = noise_level
        self.augmentation_factor = augmentation_factor
        self.random_seed = random_seed
        self.balance_classes = balance_classes

        np.random.seed(random_seed)
        random.seed(random_seed)

        logger.info(
            f"DataAugmentor: noise={noise_level}, "
            f"factor={augmentation_factor}, "
            f"balance={balance_classes}"
        )

    def augment_dataset(
        self,
        df: pd.DataFrame,
        feature_columns: List[str],
        label_column: str = "label",
    ) -> pd.DataFrame:
        """
        Augment an entire dataset DataFrame.

        Args:
            df: Input DataFrame with features and labels
            feature_columns: List of feature column names
            label_column: Name of the label column

        Returns:
            Augmented DataFrame with original + augmented samples
        """
        logger.info(f"Starting augmentation on {len(df)} samples")
        logger.info(f"Class distribution before: "
                   f"{df[label_column].value_counts().to_dict()}")

        augmented_rows = []

        for _, row in tqdm(df.iterrows(), total=len(df), desc="Augmenting"):
            features = row[feature_columns].values.astype(np.float32)
            label = row[label_column]

            # Generate augmented copies
            for _ in range(self.augmentation_factor):
                aug_features = self._augment_features(features)
                aug_row = row.copy()
                aug_row[feature_columns] = aug_features
                aug_row["augmented"] = True
                augmented_rows.append(aug_row)

        # Mark original rows
        df = df.copy()
        df["augmented"] = False

        # Combine original + augmented
        aug_df = pd.DataFrame(augmented_rows)
        combined = pd.concat([df, aug_df], ignore_index=True)

        # Balance classes if requested
        if self.balance_classes:
            combined = self._balance_classes(combined, label_column)

        # Shuffle
        combined = combined.sample(
            frac=1,
            random_state=self.random_seed
        ).reset_index(drop=True)

        logger.info(f"Augmentation complete: {len(df)} → {len(combined)} samples")
        logger.info(f"Class distribution after: "
                   f"{combined[label_column].value_counts().to_dict()}")

        return combined

    def augment_features(
        self,
        features: np.ndarray,
        num_copies: int = 1,
    ) -> List[np.ndarray]:
        """
        Generate augmented copies of a single feature vector.

        Args:
            features: Input feature vector
            num_copies: Number of augmented copies to generate

        Returns:
            List of augmented feature vectors
        """
        return [
            self._augment_features(features)
            for _ in range(num_copies)
        ]

    def _augment_features(self, features: np.ndarray) -> np.ndarray:
        """Apply random augmentation to a feature vector."""
        aug = features.copy()

        # Randomly select augmentation strategy
        strategy = random.choice([
            "noise",
            "dropout",
            "shift",
            "scale",
            "combined",
        ])

        if strategy == "noise":
            aug = self._add_gaussian_noise(aug)
        elif strategy == "dropout":
            aug = self._byte_dropout(aug)
        elif strategy == "shift":
            aug = self._byte_shift(aug)
        elif strategy == "scale":
            aug = self._feature_scale(aug)
        elif strategy == "combined":
            aug = self._add_gaussian_noise(aug)
            aug = self._byte_dropout(aug)

        # Clip to valid range [0, 1]
        aug = np.clip(aug, 0.0, 1.0)

        return aug.astype(np.float32)

    def _add_gaussian_noise(self, features: np.ndarray) -> np.ndarray:
        """
        Add Gaussian noise to simulate byte variations.
        Noise level is proportional to self.noise_level.
        """
        noise = np.random.normal(
            loc=0.0,
            scale=self.noise_level,
            size=features.shape,
        )
        return features + noise

    def _byte_dropout(
        self,
        features: np.ndarray,
        dropout_rate: float = 0.05,
    ) -> np.ndarray:
        """
        Randomly zero out features (simulates missing bytes).
        """
        mask = np.random.random(features.shape) > dropout_rate
        return features * mask

    def _byte_shift(
        self,
        features: np.ndarray,
        max_shift: int = 8,
    ) -> np.ndarray:
        """
        Shift feature values by a small random amount.
        Simulates slight header modifications malware uses.
        """
        shift = np.random.randint(-max_shift, max_shift + 1)
        shift_normalized = shift / 255.0
        return features + shift_normalized

    def _feature_scale(
        self,
        features: np.ndarray,
        scale_range: Tuple[float, float] = (0.95, 1.05),
    ) -> np.ndarray:
        """
        Scale feature values by a random factor.
        """
        scale = np.random.uniform(*scale_range)
        return features * scale

    def _partial_shuffle(
        self,
        features: np.ndarray,
        shuffle_fraction: float = 0.1,
    ) -> np.ndarray:
        """
        Shuffle a small fraction of byte positions.
        Simulates minor structural variations.
        """
        aug = features.copy()
        n = len(aug)
        num_to_shuffle = int(n * shuffle_fraction)

        if num_to_shuffle > 1:
            indices = np.random.choice(n, num_to_shuffle, replace=False)
            shuffled = aug[indices].copy()
            np.random.shuffle(shuffled)
            aug[indices] = shuffled

        return aug

    def _balance_classes(
        self,
        df: pd.DataFrame,
        label_column: str,
    ) -> pd.DataFrame:
        """
        Balance class distribution using oversampling.
        Minority class samples are duplicated with augmentation.
        """
        class_counts = df[label_column].value_counts()
        max_count = class_counts.max()

        balanced_dfs = []

        for label in class_counts.index:
            class_df = df[df[label_column] == label]
            current_count = len(class_df)

            if current_count < max_count:
                # Oversample minority class
                extra_needed = max_count - current_count
                oversampled = class_df.sample(
                    n=extra_needed,
                    replace=True,
                    random_state=self.random_seed,
                )
                class_df = pd.concat(
                    [class_df, oversampled],
                    ignore_index=True
                )

            balanced_dfs.append(class_df)

        balanced = pd.concat(balanced_dfs, ignore_index=True)
        logger.info(
            f"Class balancing: {class_counts.to_dict()} → "
            f"{balanced[label_column].value_counts().to_dict()}"
        )
        return balanced

    def augment_numpy_arrays(
        self,
        X: np.ndarray,
        y: np.ndarray,
    ) -> Tuple[np.ndarray, np.ndarray]:
        """
        Augment numpy arrays directly (for use in training loop).

        Args:
            X: Feature matrix (n_samples, n_features)
            y: Label array (n_samples,)

        Returns:
            Augmented X and y arrays
        """
        logger.info(f"Augmenting {len(X)} samples")

        aug_X = [X]
        aug_y = [y]

        for _ in range(self.augmentation_factor):
            batch_aug = np.array([
                self._augment_features(x) for x in X
            ])
            aug_X.append(batch_aug)
            aug_y.append(y)

        result_X = np.concatenate(aug_X, axis=0)
        result_y = np.concatenate(aug_y, axis=0)

        # Shuffle
        indices = np.random.permutation(len(result_X))
        result_X = result_X[indices]
        result_y = result_y[indices]

        logger.info(
            f"Augmentation complete: {len(X)} → {len(result_X)} samples"
        )

        return result_X, result_y

    def get_augmentation_stats(
        self,
        original_size: int,
    ) -> dict:
        """Return statistics about augmentation."""
        augmented_size = original_size * (1 + self.augmentation_factor)
        return {
            "original_size": original_size,
            "augmented_size": augmented_size,
            "augmentation_factor": self.augmentation_factor,
            "noise_level": self.noise_level,
            "balance_classes": self.balance_classes,
            "expansion_ratio": augmented_size / original_size,
        }
