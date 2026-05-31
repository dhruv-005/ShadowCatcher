# ============================================
# SHADOW CATCHER - Data Loader
# ============================================

import os
from pathlib import Path
from typing import Tuple, Optional

import numpy as np
import pandas as pd
import torch
from torch.utils.data import Dataset, DataLoader


# ─────────────────────────────────────────
# PYTORCH DATASET
# ─────────────────────────────────────────

class MalwareDataset(Dataset):
    """
    PyTorch Dataset for malware classification.
    Loads feature vectors and labels from CSV files.
    """

    def __init__(
        self,
        csv_path: str,
        label_col: str = "label",
        transform=None,
        normalize: bool = True,
    ):
        """
        Args:
            csv_path: Path to CSV file with features and labels
            label_col: Name of label column
            transform: Optional transform to apply to features
            normalize: Whether to clip features to [0, 1]
        """
        self.csv_path = csv_path
        self.label_col = label_col
        self.transform = transform
        self.normalize = normalize

        # Load data
        self.df = pd.read_csv(csv_path)
        self._prepare_data()

    def _prepare_data(self):
        """Prepare feature matrix and label vector."""
        # Drop non-feature columns
        drop_cols = [self.label_col, "filename"]
        drop_cols = [c for c in drop_cols if c in self.df.columns]

        # Feature matrix
        self.feature_cols = [
            c for c in self.df.columns if c not in drop_cols
        ]
        X = self.df[self.feature_cols].values.astype(np.float32)

        # Fill missing values
        X = np.nan_to_num(X, nan=0.0, posinf=1.0, neginf=0.0)

        # Clip to valid range
        if self.normalize:
            X = np.clip(X, 0.0, 1.0)

        self.X = torch.from_numpy(X)

        # Labels
        self.y = torch.from_numpy(
            self.df[self.label_col].values.astype(np.int64)
        )

        print(
            f"Loaded {len(self.df):,} samples | "
            f"{len(self.feature_cols)} features | "
            f"Classes: {dict(self.df[self.label_col].value_counts())}"
        )

    def __len__(self) -> int:
        return len(self.X)

    def __getitem__(self, idx: int) -> Tuple[torch.Tensor, torch.Tensor]:
        features = self.X[idx]
        label = self.y[idx]

        if self.transform:
            features = self.transform(features)

        return features, label

    @property
    def feature_size(self) -> int:
        return self.X.shape[1]

    @property
    def num_classes(self) -> int:
        return int(self.y.max().item()) + 1

    def get_class_weights(self) -> torch.Tensor:
        """
        Compute class weights for imbalanced datasets.
        weight[i] = total_samples / (n_classes * count[i])
        """
        labels = self.y.numpy()
        n_classes = self.num_classes
        weights = np.zeros(n_classes, dtype=np.float32)

        for i in range(n_classes):
            count = np.sum(labels == i)
            if count > 0:
                weights[i] = len(labels) / (n_classes * count)

        return torch.from_numpy(weights)


# ─────────────────────────────────────────
# DATA TRANSFORMS
# ─────────────────────────────────────────

class AddGaussianNoise:
    """Transform: Add Gaussian noise to feature tensor."""

    def __init__(self, std: float = 0.01):
        self.std = std

    def __call__(self, tensor: torch.Tensor) -> torch.Tensor:
        noise = torch.randn_like(tensor) * self.std
        return torch.clamp(tensor + noise, 0.0, 1.0)


class RandomFeatureDropout:
    """Transform: Randomly zero out features."""

    def __init__(self, p: float = 0.05):
        self.p = p

    def __call__(self, tensor: torch.Tensor) -> torch.Tensor:
        mask = torch.bernoulli(
            torch.full(tensor.shape, 1 - self.p)
        )
        return tensor * mask


class FeatureNormalizer:
    """Transform: Normalize features using pre-computed stats."""

    def __init__(self, mean: torch.Tensor, std: torch.Tensor):
        self.mean = mean
        self.std = std + 1e-8  # Prevent division by zero

    def __call__(self, tensor: torch.Tensor) -> torch.Tensor:
        return (tensor - self.mean) / self.std


# ─────────────────────────────────────────
# DATA LOADER CLASS
# ─────────────────────────────────────────

class MalwareDataLoader:
    """
    Manages creation of PyTorch DataLoaders for
    train/val/test splits.
    """

    def __init__(
        self,
        train_path: str,
        val_path: str,
        test_path: str,
        label_col: str = "label",
        augment_train: bool = True,
    ):
        """
        Args:
            train_path: Path to training CSV
            val_path: Path to validation CSV
            test_path: Path to test CSV
            label_col: Name of label column
            augment_train: Apply augmentation transforms to train set
        """
        self.train_path = train_path
        self.val_path = val_path
        self.test_path = test_path
        self.label_col = label_col
        self.augment_train = augment_train

        # Build transforms
        if augment_train:
            self.train_transform = self._build_train_transform()
        else:
            self.train_transform = None

        self.eval_transform = None

        # Load datasets
        print("\nLoading datasets...")
        self.train_dataset = MalwareDataset(
            train_path,
            label_col=label_col,
            transform=self.train_transform,
        )
        self.val_dataset = MalwareDataset(
            val_path,
            label_col=label_col,
            transform=self.eval_transform,
        )
        self.test_dataset = MalwareDataset(
            test_path,
            label_col=label_col,
            transform=self.eval_transform,
        )

        self._feature_size = self.train_dataset.feature_size

    def _build_train_transform(self):
        """Build augmentation transform for training."""
        import torchvision.transforms as transforms

        # Light augmentation - don't distort too much
        def augment(tensor):
            if torch.rand(1) > 0.5:
                tensor = AddGaussianNoise(std=0.01)(tensor)
            if torch.rand(1) > 0.7:
                tensor = RandomFeatureDropout(p=0.05)(tensor)
            return tensor

        return augment

    def get_train_loader(
        self,
        batch_size: int = 64,
        num_workers: int = 4,
        pin_memory: bool = True,
        shuffle: bool = True,
    ) -> DataLoader:
        """Get training DataLoader."""
        return DataLoader(
            self.train_dataset,
            batch_size=batch_size,
            shuffle=shuffle,
            num_workers=num_workers,
            pin_memory=pin_memory,
            drop_last=True,
        )

    def get_val_loader(
        self,
        batch_size: int = 64,
        num_workers: int = 4,
    ) -> DataLoader:
        """Get validation DataLoader."""
        return DataLoader(
            self.val_dataset,
            batch_size=batch_size,
            shuffle=False,
            num_workers=num_workers,
            pin_memory=False,
            drop_last=False,
        )

    def get_test_loader(
        self,
        batch_size: int = 64,
        num_workers: int = 4,
    ) -> DataLoader:
        """Get test DataLoader."""
        return DataLoader(
            self.test_dataset,
            batch_size=batch_size,
            shuffle=False,
            num_workers=num_workers,
            pin_memory=False,
            drop_last=False,
        )

    @property
    def feature_size(self) -> int:
        return self._feature_size

    @property
    def num_classes(self) -> int:
        return self.train_dataset.num_classes

    def get_class_weights(self) -> torch.Tensor:
        """Get class weights from training set."""
        return self.train_dataset.get_class_weights()

    def get_stats(self) -> dict:
        """Return dataset statistics."""
        return {
            "train_samples": len(self.train_dataset),
            "val_samples": len(self.val_dataset),
            "test_samples": len(self.test_dataset),
            "total_samples": (
                len(self.train_dataset)
                + len(self.val_dataset)
                + len(self.test_dataset)
            ),
            "feature_size": self.feature_size,
            "num_classes": self.num_classes,
            "class_weights": self.get_class_weights().tolist(),
        }


# ─────────────────────────────────────────
# CSV SPLITTER UTILITY
# ─────────────────────────────────────────

def split_dataset(
    input_csv: str,
    train_csv: str,
    val_csv: str,
    test_csv: str,
    train_ratio: float = 0.70,
    val_ratio: float = 0.15,
    test_ratio: float = 0.15,
    seed: int = 42,
    stratify: bool = True,
):
    """
    Split a combined CSV into train/val/test sets.

    Args:
        input_csv: Combined dataset CSV
        train_csv: Output training CSV path
        val_csv: Output validation CSV path
        test_csv: Output test CSV path
        train_ratio: Fraction for training
        val_ratio: Fraction for validation
        test_ratio: Fraction for test
        seed: Random seed for reproducibility
        stratify: Maintain class distribution in splits
    """
    assert abs(train_ratio + val_ratio + test_ratio - 1.0) < 1e-6, \
        "Ratios must sum to 1.0"

    print(f"Splitting dataset: {input_csv}")
    df = pd.read_csv(input_csv)
    df = df.sample(frac=1, random_state=seed).reset_index(drop=True)

    if stratify and "label" in df.columns:
        # Stratified split
        from sklearn.model_selection import train_test_split

        train_val, test = train_test_split(
            df,
            test_size=test_ratio,
            random_state=seed,
            stratify=df["label"],
        )
        val_size_adjusted = val_ratio / (train_ratio + val_ratio)
        train, val = train_test_split(
            train_val,
            test_size=val_size_adjusted,
            random_state=seed,
            stratify=train_val["label"],
        )
    else:
        # Simple split
        n = len(df)
        n_train = int(n * train_ratio)
        n_val = int(n * val_ratio)

        train = df.iloc[:n_train]
        val = df.iloc[n_train:n_train + n_val]
        test = df.iloc[n_train + n_val:]

    # Save splits
    os.makedirs(os.path.dirname(train_csv), exist_ok=True)
    train.to_csv(train_csv, index=False)
    val.to_csv(val_csv, index=False)
    test.to_csv(test_csv, index=False)

    print(
        f"Split complete:\n"
        f"  Train: {len(train):,} samples → {train_csv}\n"
        f"  Val:   {len(val):,} samples → {val_csv}\n"
        f"  Test:  {len(test):,} samples → {test_csv}"
    )

    return train, val, test
