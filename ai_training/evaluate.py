# ============================================
# SHADOW CATCHER - Model Evaluation Script
# ============================================

import os
import sys
import argparse
import json
from pathlib import Path

import torch
import numpy as np
from sklearn.metrics import classification_report, confusion_matrix

sys.path.append(str(Path(__file__).parent / "src"))

from data.loader import MalwareDataLoader
from models.cnn_model import CNNModel
from models.mlp_model import MLPModel
from models.classifier import ShadowBrainClassifier
from utils.metrics import MetricsTracker
from utils.visualizer import TrainingVisualizer
from utils.logger import setup_logger

# ─────────────────────────────────────────
# EVALUATOR CLASS
# ─────────────────────────────────────────

class ModelEvaluator:
    """
    Evaluate a trained Shadow Brain model on test data.
    Produces full classification report and confusion matrix.
    """

    def __init__(self, checkpoint_path: str, output_dir: str = "outputs/logs"):
        self.checkpoint_path = checkpoint_path
        self.output_dir = output_dir
        self.logger = setup_logger("evaluator", output_dir)
        self.metrics = MetricsTracker()
        self.visualizer = TrainingVisualizer(output_dir)

        os.makedirs(output_dir, exist_ok=True)

        # Load checkpoint
        self.logger.info(f"Loading checkpoint: {checkpoint_path}")
        self.checkpoint = torch.load(checkpoint_path, map_location="cpu")
        self.config = self.checkpoint.get("config", {})

        # Select device
        self.device = torch.device(
            "cuda" if torch.cuda.is_available() else "cpu"
        )
        self.logger.info(f"Using device: {self.device}")

    def _load_model(self) -> torch.nn.Module:
        """Reconstruct model from checkpoint config."""
        cfg = self.config.get("model", {})
        model_type = cfg.get("type", "cnn")

        if model_type == "cnn":
            model = CNNModel(
                input_size=cfg.get("input_size", 512),
                num_classes=cfg.get("num_classes", 2),
                dropout=cfg.get("dropout", 0.3),
            )
        elif model_type == "mlp":
            model = MLPModel(
                input_size=cfg.get("input_size", 512),
                hidden_size=cfg.get("hidden_size", 256),
                num_classes=cfg.get("num_classes", 2),
                dropout=cfg.get("dropout", 0.3),
            )
        else:
            model = ShadowBrainClassifier(
                input_size=cfg.get("input_size", 512),
                hidden_size=cfg.get("hidden_size", 256),
                num_classes=cfg.get("num_classes", 2),
                dropout=cfg.get("dropout", 0.3),
            )

        model.load_state_dict(self.checkpoint["model_state_dict"])
        model.eval()
        return model.to(self.device)

    def _get_test_loader(self):
        """Get test dataloader."""
        data_cfg = self.config.get("data", {})
        train_cfg = self.config.get("training", {})

        loader = MalwareDataLoader(
            train_path=data_cfg.get(
                "train_path", "datasets/combined/train_set.csv"
            ),
            val_path=data_cfg.get(
                "val_path", "datasets/combined/val_set.csv"
            ),
            test_path=data_cfg.get(
                "test_path", "datasets/combined/test_set.csv"
            ),
        )

        return loader.get_test_loader(
            batch_size=train_cfg.get("batch_size", 64),
            num_workers=4,
        )

    def evaluate(self) -> dict:
        """Run full evaluation on test set."""
        self.logger.info("=" * 60)
        self.logger.info("Starting Model Evaluation")
        self.logger.info("=" * 60)

        model = self._load_model()
        test_loader = self._get_test_loader()

        all_preds = []
        all_labels = []
        all_probs = []

        self.logger.info(f"Evaluating on {len(test_loader.dataset)} samples")

        with torch.no_grad():
            for features, labels in test_loader:
                features = features.to(self.device)
                outputs = model(features)
                probs = torch.softmax(outputs, dim=1)
                preds = torch.argmax(outputs, dim=1)

                all_preds.extend(preds.cpu().numpy())
                all_labels.extend(labels.numpy())
                all_probs.extend(probs.cpu().numpy())

        all_preds = np.array(all_preds)
        all_labels = np.array(all_labels)
        all_probs = np.array(all_probs)

        # Compute metrics
        metrics = self.metrics.compute(all_labels, all_preds)
        metrics["auc_roc"] = self.metrics.compute_auc(
            all_labels, all_probs[:, 1]
        )

        # Classification report
        class_names = ["Benign", "Malicious"]
        report = classification_report(
            all_labels,
            all_preds,
            target_names=class_names,
            digits=4,
        )

        # Confusion matrix
        cm = confusion_matrix(all_labels, all_preds)

        # Log results
        self.logger.info("\nClassification Report:")
        self.logger.info("\n" + report)
        self.logger.info(f"Confusion Matrix:\n{cm}")
        self.logger.info(f"AUC-ROC: {metrics['auc_roc']:.4f}")

        # Print to console
        print("\n" + "=" * 60)
        print("EVALUATION RESULTS")
        print("=" * 60)
        print(report)
        print(f"Confusion Matrix:\n{cm}")
        print(f"\nAUC-ROC Score: {metrics['auc_roc']:.4f}")
        print(f"Accuracy:      {metrics['accuracy']:.4f}")
        print(f"F1 Score:      {metrics['f1']:.4f}")
        print(f"Precision:     {metrics['precision']:.4f}")
        print(f"Recall:        {metrics['recall']:.4f}")
        print("=" * 60)

        # Save results to JSON
        results = {
            "accuracy": float(metrics["accuracy"]),
            "f1": float(metrics["f1"]),
            "precision": float(metrics["precision"]),
            "recall": float(metrics["recall"]),
            "auc_roc": float(metrics["auc_roc"]),
            "confusion_matrix": cm.tolist(),
            "classification_report": report,
            "checkpoint": self.checkpoint_path,
            "test_samples": len(all_labels),
        }

        results_path = os.path.join(self.output_dir, "eval_results.json")
        with open(results_path, "w") as f:
            json.dump(results, f, indent=2)

        self.logger.info(f"Results saved to: {results_path}")

        # Plot confusion matrix
        self.visualizer.plot_confusion_matrix(metrics)
        self.visualizer.plot_roc_curve(all_labels, all_probs[:, 1])

        return results


# ─────────────────────────────────────────
# CLI ENTRY POINT
# ─────────────────────────────────────────

def parse_args():
    parser = argparse.ArgumentParser(
        description="Evaluate Shadow Brain model"
    )
    parser.add_argument(
        "--checkpoint",
        type=str,
        default="outputs/checkpoints/best_model.pt",
        help="Path to model checkpoint"
    )
    parser.add_argument(
        "--output-dir",
        type=str,
        default="outputs/logs",
        help="Directory to save evaluation results"
    )
    return parser.parse_args()


def main():
    args = parse_args()

    if not os.path.exists(args.checkpoint):
        print(f"ERROR: Checkpoint not found: {args.checkpoint}")
        print("Run train.py first to generate a checkpoint.")
        sys.exit(1)

    evaluator = ModelEvaluator(
        checkpoint_path=args.checkpoint,
        output_dir=args.output_dir,
    )
    evaluator.evaluate()


if __name__ == "__main__":
    main()
