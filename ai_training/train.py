# ============================================
# SHADOW CATCHER - Main Training Script
# ============================================

import os
import sys
import time
import argparse
import yaml
from pathlib import Path

import torch
import torch.nn as nn
import torch.optim as optim
from torch.utils.data import DataLoader

# Add src to path
sys.path.append(str(Path(__file__).parent / "src"))

from data.loader import MalwareDataLoader
from data.validator import DataValidator
from models.classifier import ShadowBrainClassifier
from models.cnn_model import CNNModel
from models.mlp_model import MLPModel
from utils.metrics import MetricsTracker
from utils.logger import setup_logger
from utils.visualizer import TrainingVisualizer

# ─────────────────────────────────────────
# CONFIGURATION
# ─────────────────────────────────────────

DEFAULT_CONFIG = {
    "model": {
        "type": "cnn",           # cnn | mlp | ensemble
        "input_size": 512,       # bytes to analyze
        "hidden_size": 256,
        "num_classes": 2,        # 0=benign, 1=malicious
        "dropout": 0.3,
    },
    "training": {
        "epochs": 50,
        "batch_size": 64,
        "learning_rate": 0.001,
        "weight_decay": 1e-5,
        "early_stopping_patience": 10,
        "val_frequency": 1,
    },
    "data": {
        "train_path": "datasets/combined/train_set.csv",
        "val_path": "datasets/combined/val_set.csv",
        "test_path": "datasets/combined/test_set.csv",
        "num_workers": 4,
        "pin_memory": True,
    },
    "paths": {
        "checkpoint_dir": "outputs/checkpoints",
        "log_dir": "outputs/logs",
        "export_dir": "outputs/exported",
    },
}


# ─────────────────────────────────────────
# TRAINER CLASS
# ─────────────────────────────────────────

class ShadowBrainTrainer:
    """
    Main trainer for the Shadow Brain malware classifier.
    Handles training loop, validation, checkpointing.
    """

    def __init__(self, config: dict):
        self.config = config
        self.logger = setup_logger(
            name="trainer",
            log_dir=config["paths"]["log_dir"]
        )
        self.device = self._get_device()
        self.metrics = MetricsTracker()
        self.visualizer = TrainingVisualizer(
            log_dir=config["paths"]["log_dir"]
        )

        # Create output directories
        for path in config["paths"].values():
            os.makedirs(path, exist_ok=True)

        self.logger.info(f"Using device: {self.device}")
        self.logger.info(f"Config: {config}")

    def _get_device(self) -> torch.device:
        """Select best available device."""
        if torch.cuda.is_available():
            return torch.device("cuda")
        elif torch.backends.mps.is_available():
            return torch.device("mps")
        else:
            return torch.device("cpu")

    def _build_model(self) -> nn.Module:
        """Build model based on config type."""
        model_type = self.config["model"]["type"]
        cfg = self.config["model"]

        if model_type == "cnn":
            model = CNNModel(
                input_size=cfg["input_size"],
                num_classes=cfg["num_classes"],
                dropout=cfg["dropout"],
            )
        elif model_type == "mlp":
            model = MLPModel(
                input_size=cfg["input_size"],
                hidden_size=cfg["hidden_size"],
                num_classes=cfg["num_classes"],
                dropout=cfg["dropout"],
            )
        elif model_type == "ensemble":
            model = ShadowBrainClassifier(
                input_size=cfg["input_size"],
                hidden_size=cfg["hidden_size"],
                num_classes=cfg["num_classes"],
                dropout=cfg["dropout"],
            )
        else:
            raise ValueError(f"Unknown model type: {model_type}")

        return model.to(self.device)

    def _build_dataloaders(self):
        """Build train/val/test dataloaders."""
        cfg = self.config["data"]
        train_cfg = self.config["training"]

        loader = MalwareDataLoader(
            train_path=cfg["train_path"],
            val_path=cfg["val_path"],
            test_path=cfg["test_path"],
        )

        train_loader = loader.get_train_loader(
            batch_size=train_cfg["batch_size"],
            num_workers=cfg["num_workers"],
            pin_memory=cfg["pin_memory"],
        )
        val_loader = loader.get_val_loader(
            batch_size=train_cfg["batch_size"],
            num_workers=cfg["num_workers"],
        )
        test_loader = loader.get_test_loader(
            batch_size=train_cfg["batch_size"],
            num_workers=cfg["num_workers"],
        )

        self.logger.info(
            f"Dataset sizes - "
            f"Train: {len(train_loader.dataset)}, "
            f"Val: {len(val_loader.dataset)}, "
            f"Test: {len(test_loader.dataset)}"
        )

        return train_loader, val_loader, test_loader

    def _train_one_epoch(
        self,
        model: nn.Module,
        loader: DataLoader,
        optimizer: optim.Optimizer,
        criterion: nn.Module,
        epoch: int,
    ) -> dict:
        """Run one training epoch."""
        model.train()
        total_loss = 0.0
        all_preds = []
        all_labels = []

        for batch_idx, (features, labels) in enumerate(loader):
            features = features.to(self.device)
            labels = labels.to(self.device)

            optimizer.zero_grad()
            outputs = model(features)
            loss = criterion(outputs, labels)
            loss.backward()

            # Gradient clipping
            torch.nn.utils.clip_grad_norm_(model.parameters(), max_norm=1.0)

            optimizer.step()

            total_loss += loss.item()
            preds = torch.argmax(outputs, dim=1)
            all_preds.extend(preds.cpu().numpy())
            all_labels.extend(labels.cpu().numpy())

            if batch_idx % 50 == 0:
                self.logger.info(
                    f"Epoch {epoch} | "
                    f"Batch {batch_idx}/{len(loader)} | "
                    f"Loss: {loss.item():.4f}"
                )

        avg_loss = total_loss / len(loader)
        metrics = self.metrics.compute(all_labels, all_preds)
        metrics["loss"] = avg_loss

        return metrics

    def _validate(
        self,
        model: nn.Module,
        loader: DataLoader,
        criterion: nn.Module,
    ) -> dict:
        """Run validation."""
        model.eval()
        total_loss = 0.0
        all_preds = []
        all_labels = []

        with torch.no_grad():
            for features, labels in loader:
                features = features.to(self.device)
                labels = labels.to(self.device)

                outputs = model(features)
                loss = criterion(outputs, labels)

                total_loss += loss.item()
                preds = torch.argmax(outputs, dim=1)
                all_preds.extend(preds.cpu().numpy())
                all_labels.extend(labels.cpu().numpy())

        avg_loss = total_loss / len(loader)
        metrics = self.metrics.compute(all_labels, all_preds)
        metrics["loss"] = avg_loss

        return metrics

    def _save_checkpoint(
        self,
        model: nn.Module,
        optimizer: optim.Optimizer,
        epoch: int,
        metrics: dict,
        is_best: bool = False,
    ):
        """Save model checkpoint."""
        checkpoint = {
            "epoch": epoch,
            "model_state_dict": model.state_dict(),
            "optimizer_state_dict": optimizer.state_dict(),
            "metrics": metrics,
            "config": self.config,
        }

        checkpoint_dir = self.config["paths"]["checkpoint_dir"]
        path = os.path.join(checkpoint_dir, f"epoch_{epoch:03d}.pt")
        torch.save(checkpoint, path)

        if is_best:
            best_path = os.path.join(checkpoint_dir, "best_model.pt")
            torch.save(checkpoint, best_path)
            self.logger.info(f"New best model saved: {best_path}")

        self.logger.info(f"Checkpoint saved: {path}")

    def train(self):
        """Main training loop."""
        self.logger.info("=" * 60)
        self.logger.info("Starting Shadow Brain Training")
        self.logger.info("=" * 60)

        # Validate data first
        validator = DataValidator()
        validator.validate_csv(self.config["data"]["train_path"])
        validator.validate_csv(self.config["data"]["val_path"])

        # 
