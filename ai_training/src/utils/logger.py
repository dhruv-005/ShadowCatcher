# ============================================
# SHADOW CATCHER - Logger Setup
# ============================================

import os
import sys
import logging
from datetime import datetime
from pathlib import Path
from typing import Optional


# ─────────────────────────────────────────
# COLOR FORMATTER
# ─────────────────────────────────────────

class ColorFormatter(logging.Formatter):
    """
    Colored log output for terminal.
    Makes it easy to spot warnings and errors.
    """

    COLORS = {
        "DEBUG":    "\033[36m",   # Cyan
        "INFO":     "\033[32m",   # Green
        "WARNING":  "\033[33m",   # Yellow
        "ERROR":    "\033[31m",   # Red
        "CRITICAL": "\033[35m",   # Magenta
    }
    RESET = "\033[0m"
    BOLD  = "\033[1m"

    def format(self, record: logging.LogRecord) -> str:
        color = self.COLORS.get(record.levelname, self.RESET)
        record.levelname = (
            f"{color}{self.BOLD}{record.levelname:8}{self.RESET}"
        )
        record.name = f"\033[34m{record.name}\033[0m"
        return super().format(record)


# ─────────────────────────────────────────
# SETUP LOGGER FUNCTION
# ─────────────────────────────────────────

def setup_logger(
    name: str,
    log_dir: str = "outputs/logs",
    level: int = logging.INFO,
    log_to_file: bool = True,
    log_to_console: bool = True,
) -> logging.Logger:
    """
    Create and configure a logger instance.

    Args:
        name: Logger name (shown in log output)
        log_dir: Directory to save log files
        level: Logging level (DEBUG, INFO, WARNING, ERROR)
        log_to_file: Whether to write logs to file
        log_to_console: Whether to print logs to terminal

    Returns:
        Configured logger instance
    """
    logger = logging.getLogger(name)

    # Prevent duplicate handlers if called multiple times
    if logger.handlers:
        return logger

    logger.setLevel(level)

    # Log format
    fmt = "%(asctime)s | %(levelname)s | %(name)s | %(message)s"
    date_fmt = "%Y-%m-%d %H:%M:%S"

    # ── Console Handler ──
    if log_to_console:
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(level)
        console_formatter = ColorFormatter(fmt=fmt, datefmt=date_fmt)
        console_handler.setFormatter(console_formatter)
        logger.addHandler(console_handler)

    # ── File Handler ──
    if log_to_file:
        os.makedirs(log_dir, exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        log_file = os.path.join(log_dir, f"{name}_{timestamp}.log")

        file_handler = logging.FileHandler(log_file, encoding="utf-8")
        file_handler.setLevel(logging.DEBUG)
        file_formatter = logging.Formatter(fmt=fmt, datefmt=date_fmt)
        file_handler.setFormatter(file_formatter)
        logger.addHandler(file_handler)

        # Also create a latest.log symlink
        latest_path = os.path.join(log_dir, f"{name}_latest.log")
        try:
            if os.path.exists(latest_path):
                os.remove(latest_path)
            os.symlink(log_file, latest_path)
        except (OSError, NotImplementedError):
            pass  # Symlinks may not be supported on all systems

    return logger


# ─────────────────────────────────────────
# TRAINING LOGGER
# ─────────────────────────────────────────

class TrainingLogger:
    """
    Specialized logger for training progress.
    Handles epoch logging, metric tracking, and CSV export.
    """

    def __init__(
        self,
        log_dir: str = "outputs/logs",
        experiment_name: str = "shadow_brain",
    ):
        self.log_dir = log_dir
        self.experiment_name = experiment_name
        self.logger = setup_logger(
            name=f"training_{experiment_name}",
            log_dir=log_dir,
        )

        os.makedirs(log_dir, exist_ok=True)

        # CSV log file for metrics
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.csv_path = os.path.join(
            log_dir,
            f"{experiment_name}_{timestamp}_metrics.csv",
        )
        self._csv_initialized = False

    def log_epoch(
        self,
        epoch: int,
        train_metrics: dict,
        val_metrics: dict,
    ):
        """Log metrics for one epoch."""
        self.logger.info(
            f"Epoch {epoch:3d} | "
            f"Loss: {train_metrics.get('loss', 0):.4f} → "
            f"{val_metrics.get('loss', 0):.4f} | "
            f"Acc: {train_metrics.get('accuracy', 0):.4f} → "
            f"{val_metrics.get('accuracy', 0):.4f} | "
            f"F1: {val_metrics.get('f1', 0):.4f} | "
            f"FNR: {val_metrics.get('false_negative_rate', 0):.4f}"
        )

        # Write to CSV
        self._write_csv(epoch, train_metrics, val_metrics)

    def log_best_model(self, epoch: int, metrics: dict):
        """Log when a new best model is saved."""
        self.logger.info(
            f"🏆 NEW BEST MODEL at epoch {epoch} | "
            f"Acc: {metrics.get('accuracy', 0):.4f} | "
            f"F1: {metrics.get('f1', 0):.4f}"
        )

    def log_early_stopping(self, epoch: int, patience: int):
        """Log early stopping trigger."""
        self.logger.warning(
            f"Early stopping triggered at epoch {epoch} "
            f"(patience={patience})"
        )

    def log_threat_detected(self, filename: str, confidence: float):
        """Log a threat detection event."""
        self.logger.warning(
            f"🚨 THREAT DETECTED: {filename} "
            f"(confidence={confidence:.2%})"
        )

    def _write_csv(
        self,
        epoch: int,
        train_metrics: dict,
        val_metrics: dict,
    ):
        """Write metrics to CSV file."""
        import csv

        row = {
            "epoch": epoch,
            "train_loss": train_metrics.get("loss", 0),
            "train_accuracy": train_metrics.get("accuracy", 0),
            "train_f1": train_metrics.get("f1", 0),
            "val_loss": val_metrics.get("loss", 0),
            "val_accuracy": val_metrics.get("accuracy", 0),
            "val_f1": val_metrics.get("f1", 0),
            "val_precision": val_metrics.get("precision", 0),
            "val_recall": val_metrics.get("recall", 0),
            "val_fnr": val_metrics.get("false_negative_rate", 0),
            "val_fpr": val_metrics.get("false_positive_rate", 0),
        }

        write_header = not self._csv_initialized
        with open(self.csv_path, "a", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=row.keys())
            if write_header:
                writer.writeheader()
                self._csv_initialized = True
            writer.writerow(row)


# ─────────────────────────────────────────
# CONVENIENCE FUNCTIONS
# ─────────────────────────────────────────

def get_logger(name: str) -> logging.Logger:
    """Get existing logger by name."""
    return logging.getLogger(name)


def set_log_level(name: str, level: str = "INFO"):
    """Change log level of existing logger."""
    logger = logging.getLogger(name)
    logger.setLevel(getattr(logging, level.upper(), logging.INFO))


def log_system_info(logger: logging.Logger):
    """Log system and environment information."""
    import platform
    import torch

    logger.info("=" * 50)
    logger.info("SYSTEM INFORMATION")
    logger.info("=" * 50)
    logger.info(f"OS:         {platform.system()} {platform.release()}")
    logger.info(f"Python:     {sys.version.split()[0]}")
    logger.info(f"PyTorch:    {torch.__version__}")
    logger.info(f"CUDA:       {torch.cuda.is_available()}")

    if torch.cuda.is_available():
        logger.info(
            f"GPU:        {torch.cuda.get_device_name(0)}"
        )
        logger.info(
            f"VRAM:       "
            f"{torch.cuda.get_device_properties(0).total_memory / 1e9:.1f} GB"
        )
    logger.info("=" * 50)
