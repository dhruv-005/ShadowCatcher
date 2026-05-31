# ============================================
# SHADOW CATCHER - ONNX Export Script
# ============================================

import os
import sys
import argparse
from pathlib import Path

import torch
import torch.nn as nn
import onnx
import onnxsim

sys.path.append(str(Path(__file__).parent / "src"))

from models.cnn_model import CNNModel
from models.mlp_model import MLPModel
from models.classifier import ShadowBrainClassifier
from utils.logger import setup_logger

# ─────────────────────────────────────────
# ONNX EXPORTER CLASS
# ─────────────────────────────────────────

class ONNXExporter:
    """
    Export trained PyTorch model to ONNX format.
    The exported model is bundled with the Flutter app.
    """

    def __init__(
        self,
        checkpoint_path: str,
        output_path: str = "outputs/exported/shadow_brain.onnx",
    ):
        self.checkpoint_path = checkpoint_path
        self.output_path = output_path
        self.logger = setup_logger("exporter", "outputs/logs")

        os.makedirs(os.path.dirname(output_path), exist_ok=True)

        # Load checkpoint
        self.logger.info(f"Loading checkpoint: {checkpoint_path}")
        self.checkpoint = torch.load(checkpoint_path, map_location="cpu")
        self.config = self.checkpoint.get("config", {})

    def _load_model(self) -> nn.Module:
        """Reconstruct and load model from checkpoint."""
        cfg = self.config.get("model", {})
        model_type = cfg.get("type", "cnn")

        if model_type == "cnn":
            model = CNNModel(
                input_size=cfg.get("input_size", 512),
                num_classes=cfg.get("num_classes", 2),
                dropout=0.0,  # Disable dropout for inference
            )
        elif model_type == "mlp":
            model = MLPModel(
                input_size=cfg.get("input_size", 512),
                hidden_size=cfg.get("hidden_size", 256),
                num_classes=cfg.get("num_classes", 2),
                dropout=0.0,
            )
        else:
            model = ShadowBrainClassifier(
                input_size=cfg.get("input_size", 512),
                hidden_size=cfg.get("hidden_size", 256),
                num_classes=cfg.get("num_classes", 2),
                dropout=0.0,
            )

        model.load_state_dict(self.checkpoint["model_state_dict"])
        model.eval()

        self.logger.info(f"Model type: {model_type}")
        self.logger.info(
            f"Parameters: {sum(p.numel() for p in model.parameters()):,}"
        )

        return model

    def export(
        self,
        simplify: bool = True,
        dynamic_batch: bool = True,
        opset_version: int = 17,
    ) -> str:
        """
        Export model to ONNX format.

        Args:
            simplify: Run onnx-simplifier to reduce model size
            dynamic_batch: Allow variable batch sizes at runtime
            opset_version: ONNX opset version to use

        Returns:
            Path to exported ONNX file
        """
        self.logger.info("=" * 60)
        self.logger.info("Starting ONNX Export")
        self.logger.info("=" * 60)

        model = self._load_model()
        input_size = self.config.get("model", {}).get("input_size", 512)

        # Create dummy input
        dummy_input = torch.randn(1, input_size)

        self.logger.info(f"Input shape: {dummy_input.shape}")
        self.logger.info(f"Output path: {self.output_path}")
        self.logger.info(f"ONNX opset: {opset_version}")

        # Dynamic axes for variable batch size
        dynamic_axes = None
        if dynamic_batch:
            dynamic_axes = {
                "input": {0: "batch_size"},
                "output": {0: "batch_size"},
            }

        # Export to ONNX
        torch.onnx.export(
            model,
            dummy_input,
            self.output_path,
            opset_version=opset_version,
            input_names=["input"],
            output_names=["output"],
            dynamic_axes=dynamic_axes,
            do_constant_folding=True,
            export_params=True,
            verbose=False,
        )

        self.logger.info("PyTorch → ONNX export complete")

        # Verify the exported model
        self.logger.info("Verifying ONNX model...")
        onnx_model = onnx.load(self.output_path)
        onnx.checker.check_model(onnx_model)
        self.logger.info("ONNX model verification passed ✓")

        # Simplify model
        if simplify:
            self.logger.info("Running ONNX simplifier...")
            simplified_model, success = onnxsim.simplify(onnx_model)
            if success:
                onnx.save(simplified_model, self.output_path)
                self.logger.info("Model simplified successfully ✓")
            else:
                self.logger.warning("Simplification failed, using original")

        # Print model info
        file_size_mb = os.path.getsize(self.output_path) / (1024 * 1024)
        self.logger.info(f"Model file size: {file_size_mb:.2f} MB")

        # Copy to Flutter assets
        flutter_path = (
            "../frontend/assets/ai/shadow_brain.onnx"
        )
        if os.path.exists(os.path.dirname(flutter_path)):
            import shutil
            shutil.copy(self.output_path, flutter_path)
            self.logger.info(f"Copied to Flutter assets: {flutter_path}")
        else:
            self.logger.warning(
                "Flutter assets directory not found. "
                "Copy manually to frontend/assets/ai/shadow_brain.onnx"
            )

        print("\n" + "=" * 60)
        print("ONNX EXPORT COMPLETE")
        print("=" * 60)
        print(f"Output path : {self.output_path}")
        print(f"File size   : {file_size_mb:.2f} MB")
        print(f"Input shape : [batch_size, {input_size}]")
        print(f"Output shape: [batch_size, 2]")
        print("  Output[0] = Benign probability")
        print("  Output[1] = Malicious probability")
        print("=" * 60)
        print("Run verify_onnx.py to test the exported model")

        return self.output_path


# ─────────────────────────────────────────
# CLI ENTRY POINT
# ─────────────────────────────────────────

def parse_args():
    parser = argparse.ArgumentParser(
        description="Export Shadow Brain model to ONNX"
    )
    parser.add_argument(
        "--checkpoint",
        type=str,
        default="outputs/checkpoints/best_model.pt",
        help="Path to trained model checkpoint"
    )
    parser.add_argument(
        "--output",
        type=str,
        default="outputs/exported/shadow_brain.onnx",
        help="Output path for ONNX model"
    )
    parser.add_argument(
        "--no-simplify",
        action="store_true",
        help="Skip ONNX simplification step"
    )
    parser.add_argument(
        "--static-batch",
        action="store_true",
        help="Use static batch size instead of dynamic"
    )
    parser.add_argument(
        "--opset",
        type=int,
        default=17,
        help="ONNX opset version"
    )
    return parser.parse_args()


def main():
    args = parse_args()

    if not os.path.exists(args.checkpoint):
        print(f"ERROR: Checkpoint not found: {args.checkpoint}")
        print("Run train.py first.")
        sys.exit(1)

    exporter = ONNXExporter(
        checkpoint_path=args.checkpoint,
        output_path=args.output,
    )
    exporter.export(
        simplify=not args.no_simplify,
        dynamic_batch=not args.static_batch,
        opset_version=args.opset,
    )


if __name__ == "__main__":
    main()
