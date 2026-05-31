# ============================================
# SHADOW CATCHER - Metrics Tracker
# ============================================

from typing import List, Dict, Optional
import numpy as np
from sklearn.metrics import (
    accuracy_score,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
    confusion_matrix,
    classification_report,
    average_precision_score,
)


# ─────────────────────────────────────────
# METRICS TRACKER CLASS
# ─────────────────────────────────────────

class MetricsTracker:
    """
    Track and compute classification metrics
    for malware detection model evaluation.

    Metrics computed:
    - Accuracy
    - F1 Score (weighted)
    - Precision
    - Recall
    - AUC-ROC
    - False Positive Rate (critical for security)
    - False Negative Rate (critical for security)
    - Confusion Matrix
    """

    def __init__(self):
        self.history: List[Dict] = []
        self.best_metrics: Dict = {}

    # ─────────────────────────────────────
    # CORE METRICS
    # ─────────────────────────────────────

    def compute(
        self,
        y_true: List[int],
        y_pred: List[int],
        average: str = "weighted",
    ) -> Dict:
        """
        Compute all classification metrics.

        Args:
            y_true: Ground truth labels
            y_pred: Predicted labels
            average: Averaging strategy for multi-class

        Returns:
            Dictionary of metric name → value
        """
        y_true = np.array(y_true)
        y_pred = np.array(y_pred)

        metrics = {}

        # Basic metrics
        metrics["accuracy"] = float(
            accuracy_score(y_true, y_pred)
        )
        metrics["f1"] = float(
            f1_score(
                y_true, y_pred,
                average=average,
                zero_division=0,
            )
        )
        metrics["precision"] = float(
            precision_score(
                y_true, y_pred,
                average=average,
                zero_division=0,
            )
        )
        metrics["recall"] = float(
            recall_score(
                y_true, y_pred,
                average=average,
                zero_division=0,
            )
        )

        # Per-class metrics
        metrics["f1_benign"] = float(
            f1_score(
                y_true, y_pred,
                pos_label=0,
                average="binary",
                zero_division=0,
            )
        )
        metrics["f1_malicious"] = float(
            f1_score(
                y_true, y_pred,
                pos_label=1,
                average="binary",
                zero_division=0,
            )
        )

        # Security-critical metrics from confusion matrix
        cm = confusion_matrix(y_true, y_pred, labels=[0, 1])
        if cm.shape == (2, 2):
            tn, fp, fn, tp = cm.ravel()
            total = tn + fp + fn + tp

            # False Positive Rate = FP / (FP + TN)
            # = Rate of benign files flagged as malware (annoyance)
            fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
            metrics["false_positive_rate"] = float(fpr)

            # False Negative Rate = FN / (FN + TP)
            # = Rate of malware files missed (DANGER!)
            fnr = fn / (fn + tp) if (fn + tp) > 0 else 0.0
            metrics["false_negative_rate"] = float(fnr)

            metrics["true_positive_rate"] = float(
                tp / (tp + fn) if (tp + fn) > 0 else 0.0
            )
            metrics["true_negative_rate"] = float(
                tn / (tn + fp) if (tn + fp) > 0 else 0.0
            )

            metrics["confusion_matrix"] = cm.tolist()
            metrics["tp"] = int(tp)
            metrics["tn"] = int(tn)
            metrics["fp"] = int(fp)
            metrics["fn"] = int(fn)

        # Matthews Correlation Coefficient
        metrics["mcc"] = float(self._mcc(y_true, y_pred))

        return metrics

    def compute_auc(
        self,
        y_true: np.ndarray,
        y_prob: np.ndarray,
    ) -> float:
        """
        Compute AUC-ROC score.

        Args:
            y_true: Ground truth labels
            y_prob: Predicted probabilities for positive class

        Returns:
            AUC-ROC score
        """
        try:
            return float(roc_auc_score(y_true, y_prob))
        except ValueError:
            return 0.0

    def compute_average_precision(
        self,
        y_true: np.ndarray,
        y_prob: np.ndarray,
    ) -> float:
        """Compute Average Precision (PR-AUC)."""
        try:
            return float(average_precision_score(y_true, y_prob))
        except ValueError:
            return 0.0

    # ─────────────────────────────────────
    # HISTORY TRACKING
    # ─────────────────────────────────────

    def update(self, metrics: Dict, epoch: int):
        """Add metrics for current epoch to history."""
        metrics["epoch"] = epoch
        self.history.append(metrics.copy())

        # Track best metrics
        if not self.best_metrics or (
            metrics.get("accuracy", 0) >
            self.best_metrics.get("accuracy", 0)
        ):
            self.best_metrics = metrics.copy()
            self.best_metrics["best_epoch"] = epoch

    def get_history(self) -> List[Dict]:
        """Return full training history."""
        return self.history.copy()

    def get_best(self) -> Dict:
        """Return best metrics achieved."""
        return self.best_metrics.copy()

    def get_metric_history(self, metric_name: str) -> List[float]:
        """Return history of a specific metric."""
        return [
            h.get(metric_name, 0.0)
            for h in self.history
        ]

    # ─────────────────────────────────────
    # REPORTING
    # ─────────────────────────────────────

    def print_report(self, metrics: Dict):
        """Print formatted metrics report."""
        print("\n" + "─" * 50)
        print("METRICS REPORT")
        print("─" * 50)
        print(f"  Accuracy           : {metrics.get('accuracy', 0):.4f}")
        print(f"  F1 Score (weighted): {metrics.get('f1', 0):.4f}")
        print(f"  Precision          : {metrics.get('precision', 0):.4f}")
        print(f"  Recall             : {metrics.get('recall', 0):.4f}")
        print(f"  AUC-ROC            : {metrics.get('auc_roc', 0):.4f}")
        print(f"  MCC                : {metrics.get('mcc', 0):.4f}")
        print()
        print(f"  F1 Benign          : {metrics.get('f1_benign', 0):.4f}")
        print(f"  F1 Malicious       : {metrics.get('f1_malicious', 0):.4f}")
        print()
        print("  ⚠️  Security Metrics:")
        print(
            f"  False Positive Rate: "
            f"{metrics.get('false_positive_rate', 0):.4f} "
            f"(benign flagged as malware)"
        )
        print(
            f"  False Negative Rate: "
            f"{metrics.get('false_negative_rate', 0):.4f} "
            f"(malware missed!) ← minimize this"
        )
        print()

        cm = metrics.get("confusion_matrix")
        if cm:
            print("  Confusion Matrix:")
            print(f"    TN={metrics.get('tn',0):5d}  FP={metrics.get('fp',0):5d}")
            print(f"    FN={metrics.get('fn',0):5d}  TP={metrics.get('tp',0):5d}")
        print("─" * 50)

    def is_good_enough(
        self,
        metrics: Dict,
        min_accuracy: float = 0.95,
        max_fnr: float = 0.02,
    ) -> bool:
        """
        Check if model meets minimum quality thresholds.

        Security requirements:
        - Accuracy >= 95%
        - False Negative Rate <= 2% (must not miss malware!)
        """
        accuracy_ok = metrics.get("accuracy", 0) >= min_accuracy
        fnr_ok = metrics.get("false_negative_rate", 1.0) <= max_fnr

        if not accuracy_ok:
            print(
                f"⚠ Accuracy {metrics.get('accuracy', 0):.4f} "
                f"below threshold {min_accuracy}"
            )
        if not fnr_ok:
            print(
                f"⚠ FNR {metrics.get('false_negative_rate', 0):.4f} "
                f"above threshold {max_fnr} - too many missed threats!"
            )

        return accuracy_ok and fnr_ok

    # ─────────────────────────────────────
    # UTILITIES
    # ─────────────────────────────────────

    def _mcc(
        self,
        y_true: np.ndarray,
        y_pred: np.ndarray,
    ) -> float:
        """
        Matthews Correlation Coefficient.
        Better metric than accuracy for imbalanced datasets.
        Range: [-1, 1] where 1 = perfect
        """
        try:
            cm = confusion_matrix(y_true, y_pred, labels=[0, 1])
            if cm.shape != (2, 2):
                return 0.0

            tn, fp, fn, tp = cm.ravel()
            numerator = (tp * tn) - (fp * fn)
            denominator = np.sqrt(
                (tp + fp) * (tp + fn) *
                (tn + fp) * (tn + fn)
            )
            if denominator == 0:
                return 0.0
            return float(numerator / denominator)
        except Exception:
            return 0.0

    def reset(self):
        """Reset history."""
        self.history = []
        self.best_metrics = {}
