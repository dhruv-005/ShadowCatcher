# ============================================
# SHADOW CATCHER - Training Visualizer
# ============================================

import os
from typing import List, Dict, Optional
import numpy as np
import matplotlib
matplotlib.use("Agg")  # Non-interactive backend
import matplotlib.pyplot as plt
import matplotlib.gridspec as gridspec
import seaborn as sns


# ─────────────────────────────────────────
# VISUALIZER CLASS
# ─────────────────────────────────────────

class TrainingVisualizer:
    """
    Generate training visualizations and plots.

    Produces:
    - Training/validation loss curves
    - Accuracy curves
    - Confusion matrix heatmap
    - ROC curve
    - Precision-Recall curve
    - Feature importance plot
    """

    def __init__(
        self,
        log_dir: str = "outputs/logs",
        style: str = "darkgrid",
    ):
        self.log_dir = log_dir
        os.makedirs(log_dir, exist_ok=True)
        sns.set_style(style)
        plt.rcParams.update({
            "figure.dpi": 120,
            "font.size": 11,
            "axes.titlesize": 13,
            "figure.facecolor": "white",
        })

    # ─────────────────────────────────────
    # TRAINING CURVES
    # ─────────────────────────────────────

    def plot_training_curves(
        self,
        train_history: List[Dict],
        val_history: List[Dict],
        save_path: str = None,
    ):
        """
        Plot training and validation loss/accuracy curves.
        """
        if not train_history:
            return

        if save_path is None:
            save_path = os.path.join(self.log_dir, "training_curves.png")

        fig, axes = plt.subplots(2, 2, figsize=(14, 10))
        fig.suptitle("Shadow Brain Training Progress", fontsize=16, y=1.02)

        epochs_train = range(1, len(train_history) + 1)
        epochs_val = range(1, len(val_history) + 1)

        # ── Loss ──
        ax = axes[0, 0]
        train_loss = [h.get("loss", 0) for h in train_history]
        val_loss = [h.get("loss", 0) for h in val_history]
        ax.plot(epochs_train, train_loss, "b-o", label="Train", markersize=3)
        ax.plot(epochs_val, val_loss, "r-o", label="Val", markersize=3)
        ax.set_title("Loss")
        ax.set_xlabel("Epoch")
        ax.set_ylabel("Cross-Entropy Loss")
        ax.legend()
        ax.grid(True, alpha=0.3)

        # ── Accuracy ──
        ax = axes[0, 1]
        train_acc = [h.get("accuracy", 0) for h in train_history]
        val_acc = [h.get("accuracy", 0) for h in val_history]
        ax.plot(epochs_train, train_acc, "b-o", label="Train", markersize=3)
        ax.plot(epochs_val, val_acc, "r-o", label="Val", markersize=3)
        ax.axhline(y=0.95, color="g", linestyle="--", alpha=0.7, label="Target 95%")
        ax.set_title("Accuracy")
        ax.set_xlabel("Epoch")
        ax.set_ylabel("Accuracy")
        ax.legend()
        ax.grid(True, alpha=0.3)
        ax.set_ylim(0, 1.05)

        # ── F1 Score ──
        ax = axes[1, 0]
        train_f1 = [h.get("f1", 0) for h in train_history]
        val_f1 = [h.get("f1", 0) for h in val_history]
        ax.plot(epochs_train, train_f1, "b-o", label="Train F1", markersize=3)
        ax.plot(epochs_val, val_f1, "r-o", label="Val F1", markersize=3)
        ax.set_title("F1 Score")
        ax.set_xlabel("Epoch")
        ax.set_ylabel("F1 Score")
        ax.legend()
        ax.grid(True, alpha=0.3)
        ax.set_ylim(0, 1.05)

        # ── FNR (False Negative Rate) ──
        ax = axes[1, 1]
        val_fnr = [h.get("false_negative_rate", 0) for h in val_history]
        val_fpr = [h.get("false_positive_rate", 0) for h in val_history]
        ax.plot(epochs_val, val_fnr, "r-o", label="FNR (missed malware)", markersize=3)
        ax.plot(epochs_val, val_fpr, "y-o", label="FPR (false alarms)", markersize=3)
        ax.axhline(y=0.02, color="r", linestyle="--", alpha=0.7, label="FNR target 2%")
        ax.set_title("Security Metrics")
        ax.set_xlabel("Epoch")
        ax.set_ylabel("Rate")
        ax.legend()
        ax.grid(True, alpha=0.3)
        ax.set_ylim(0, 0.5)

        plt.tight_layout()
        plt.savefig(save_path, bbox_inches="tight", dpi=120)
        plt.close()
        print(f"Training curves saved: {save_path}")

    # ─────────────────────────────────────
    # CONFUSION MATRIX
    # ─────────────────────────────────────

    def plot_confusion_matrix(
        self,
        metrics: Dict,
        save_path: str = None,
        class_names: List[str] = None,
    ):
        """Plot confusion matrix heatmap."""
        cm = metrics.get("confusion_matrix")
        if cm is None:
            return

        if save_path is None:
            save_path = os.path.join(self.log_dir, "confusion_matrix.png")

        if class_names is None:
            class_names = ["Benign", "Malicious"]

        cm = np.array(cm)
        cm_normalized = cm.astype(float) / cm.sum(axis=1, keepdims=True)

        fig, axes = plt.subplots(1, 2, figsize=(14, 5))
        fig.suptitle("Confusion Matrix - Shadow Brain", fontsize=14)

        # Raw counts
        ax = axes[0]
        sns.heatmap(
            cm,
            annot=True,
            fmt="d",
            cmap="Blues",
            xticklabels=class_names,
            yticklabels=class_names,
            ax=ax,
            linewidths=0.5,
        )
        ax.set_title("Raw Counts")
        ax.set_ylabel("True Label")
        ax.set_xlabel("Predicted Label")

        # Normalized
        ax = axes[1]
        sns.heatmap(
            cm_normalized,
            annot=True,
            fmt=".3f",
            cmap="Blues",
            xticklabels=class_names,
            yticklabels=class_names,
            ax=ax,
            linewidths=0.5,
            vmin=0,
            vmax=1,
        )
        ax.set_title("Normalized (Row %)")
        ax.set_ylabel("True Label")
        ax.set_xlabel("Predicted Label")

        # Add metric annotations
        acc = metrics.get("accuracy", 0)
        f1 = metrics.get("f1", 0)
        fnr = metrics.get("false_negative_rate", 0)
        fpr = metrics.get("false_positive_rate", 0)

        fig.text(
            0.5, -0.02,
            f"Accuracy: {acc:.4f} | F1: {f1:.4f} | "
            f"FNR: {fnr:.4f} | FPR: {fpr:.4f}",
            ha="center",
            fontsize=11,
        )

        plt.tight_layout()
        plt.savefig(save_path, bbox_inches="tight", dpi=120)
        plt.close()
        print(f"Confusion matrix saved: {save_path}")

    # ─────────────────────────────────────
    # ROC CURVE
    # ─────────────────────────────────────

    def plot_roc_curve(
        self,
        y_true: np.ndarray,
        y_prob: np.ndarray,
        save_path: str = None,
    ):
        """Plot ROC curve with AUC score."""
        from sklearn.metrics import roc_curve, auc

        if save_path is None:
            save_path = os.path.join(self.log_dir, "roc_curve.png")

        fpr, tpr, thresholds = roc_curve(y_true, y_prob)
        roc_auc = auc(fpr, tpr)

        fig, ax = plt.subplots(figsize=(8, 6))

        ax.plot(
            fpr, tpr,
            color="darkorange",
            lw=2,
            label=f"ROC Curve (AUC = {roc_auc:.4f})",
        )
        ax.plot([0, 1], [0, 1], "k--", lw=1, label="Random Classifier")
        ax.fill_between(fpr, tpr, alpha=0.1, color="darkorange")

        # Mark optimal threshold
        optimal_idx = np.argmax(tpr - fpr)
        optimal_fpr = fpr[optimal_idx]
        optimal_tpr = tpr[optimal_idx]
        optimal_threshold = thresholds[optimal_idx]

        ax.plot(
            optimal_fpr, optimal_tpr,
            "ro", markersize=8,
            label=f"Optimal (threshold={optimal_threshold:.2f})",
        )

        ax.set_xlim([-0.01, 1.01])
        ax.set_ylim([-0.01, 1.01])
        ax.set_xlabel("False Positive Rate")
        ax.set_ylabel("True Positive Rate")
        ax.set_title("ROC Curve - Shadow Brain Malware Detector")
        ax.legend(loc="lower right")
        ax.grid(True, alpha=0.3)

        plt.tight_layout()
        plt.savefig(save_path, bbox_inches="tight", dpi=120)
        plt.close()
        print(f"ROC curve saved: {save_path}")

    # ─────────────────────────────────────
    # FEATURE IMPORTANCE
    # ─────────────────────────────────────

    def plot_feature_importance(
        self,
        importance_scores: np.ndarray,
        feature_names: List[str] = None,
        top_k: int = 30,
        save_path: str = None,
    ):
        """Plot top-k most important features."""
        if save_path is None:
            save_path = os.path.join(self.log_dir, "feature_importance.png")

        # Get top-k features
        top_indices = np.argsort(importance_scores)[-top_k:][::-1]
        top_scores = importance_scores[top_indices]

        if feature_names:
            top_names = [feature_names[i] for i in top_indices]
        else:
            top_names = [f"Feature {i}" for i in top_indices]

        fig, ax = plt.subplots(figsize=(10, max(6, top_k * 0.3)))

        colors = plt.cm.RdYlGn(top_scores / top_scores.max())
        bars = ax.barh(range(top_k), top_scores, color=colors)

        ax.set_yticks(range(top_k))
        ax.set_yticklabels(top_names, fontsize=9)
        ax.set_xlabel("Importance Score")
        ax.set_title(f"Top {top_k} Most Important Features")
        ax.grid(True, alpha=0.3, axis="x")

        # Add value labels
        for bar, score in zip(bars, top_scores):
            ax.text(
                bar.get_width() + 0.001,
                bar.get_y() + bar.get_height() / 2,
                f"{score:.3f}",
                va="center",
                fontsize=8,
            )

        plt.tight_layout()
        plt.savefig(save_path, bbox_inches="tight", dpi=120)
        plt.close()
        print(f"Feature importance saved: {save_path}")

    # ─────────────────────────────────────
    # BYTE DISTRIBUTION
    # ─────────────────────────────────────

    def plot_byte_distributions(
        self,
        benign_bytes: np.ndarray,
        malicious_bytes: np.ndarray,
        save_path: str = None,
    ):
        """
        Plot byte frequency distributions for
        benign vs malicious files.
        """
        if save_path is None:
            save_path = os.path.join(self.log_dir, "byte_distributions.png")

        fig, axes = plt.subplots(1, 2, figsize=(16, 5))
        fig.suptitle("Byte Frequency Distribution", fontsize=14)

        for ax, data, title, color in zip(
            axes,
            [benign_bytes, malicious_bytes],
            ["Benign Files", "Malicious Files"],
            ["steelblue", "crimson"],
        ):
            if len(data) == 0:
                continue

            mean_dist = np.mean(data[:, :256], axis=0)
            x = np.arange(256)

            ax.bar(x, mean_dist, color=color, alpha=0.7, width=1.0)
            ax.set_title(title)
            ax.set_xlabel("Byte Value (0-255)")
            ax.set_ylabel("Mean Frequency")
            ax.grid(True, alpha=0.3)

        plt.tight_layout()
        plt.savefig(save_path, bbox_inches="tight", dpi=120)
        plt.close()
        print(f"Byte distributions saved: {save_path}")
