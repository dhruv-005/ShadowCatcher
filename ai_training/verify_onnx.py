# ============================================
# SHADOW CATCHER - ONNX Verification Script
# ============================================

import os
import sys
import argparse
import time
from pathlib import Path

import numpy as np
import torch
import onnx
import onnxruntime as ort

sys.path.append(str(Path(__file__).parent / "src"))

from models.cnn_model import CNNModel
from models.mlp_model import MLPModel
from models.classifier import ShadowBrainClassifier
from utils.logger import setup_logger


# ─────────────────────────────────────────
# VERIFIER CLASS
# ─────────────────────────────────────────

class ONNXVerifier:
    """
    Verify that the exported ONNX model:
    1. Loads successfully
    2. Produces correct output shapes
    3. Matches PyTorch model outputs
    4. Runs within acceptable time limits
    5. Handles edge cases correctly
    """

    def __init__(
        self,
        onnx_path: str,
        checkpoint_path: str = None,
    ):
        self.onnx_path = onnx_path
        self.checkpoint_path = checkpoint_path
        self.logger = setup_logger("verifier", "outputs/logs")
        self.input_size = 512
        self.passed = 0
        self.failed = 0

    def _check(self, name: str, condition: bool, details: str = ""):
        """Record a test result."""
        if condition:
            self.passed += 1
            self.logger.info(f"  ✓ PASS: {name}")
            print(f"  ✓ PASS: {name}")
        else:
            self.failed += 1
            self.logger.error(f"  ✗ FAIL: {name} - {details}")
            print(f"  ✗ FAIL: {name} - {details}")

    def test_model_loads(self) -> bool:
        """Test 1: Model loads without errors."""
        print("\n[Test 1] Model Loading")
        try:
            model = onnx.load(self.onnx_path)
            onnx.checker.check_model(model)
            self._check("ONNX model loads", True)
            self._check("ONNX model validates", True)

            # Check inputs
            inputs = model.graph.input
            self._check(
                "Model has input node",
                len(inputs) > 0
            )

            # Check outputs
            outputs = model.graph.output
            self._check(
                "Model has output node",
                len(outputs) > 0
            )

            return True
        except Exception as e:
            self._check("ONNX model loads", False, str(e))
            return False

    def test_inference_session(self) -> ort.InferenceSession:
        """Test 2: Create inference session."""
        print("\n[Test 2] Inference Session")
        try:
            providers = ["CPUExecutionProvider"]
            session = ort.InferenceSession(
                self.onnx_path,
                providers=providers,
            )
            self._check("ORT session created", True)

            # Check input info
            input_info = session.get_inputs()[0]
            self.logger.info(f"Input name: {input_info.name}")
            self.logger.info(f"Input shape: {input_info.shape}")
            self.logger.info(f"Input type: {input_info.type}")

            self._check(
                "Input name is 'input'",
                input_info.name == "input"
            )

            # Check output info
            output_info = session.get_outputs()[0]
            self._check(
                "Output name is 'output'",
                output_info.name == "output"
            )

            return session
        except Exception as e:
            self._check("ORT session created", False, str(e))
            return None

    def test_output_shape(self, session: ort.InferenceSession):
        """Test 3: Output shape is correct."""
        print("\n[Test 3] Output Shape")
        try:
            # Single sample
            dummy = np.random.randn(1, self.input_size).astype(np.float32)
            output = session.run(["output"], {"input": dummy})[0]

            self._check(
                f"Single sample output shape [1, 2]",
                output.shape == (1, 2),
                f"Got: {output.shape}"
            )

            # Batch of 16
            batch = np.random.randn(16, self.input_size).astype(np.float32)
            output_batch = session.run(["output"], {"input": batch})[0]

            self._check(
                "Batch output shape [16, 2]",
                output_batch.shape == (16, 2),
                f"Got: {output_batch.shape}"
            )

        except Exception as e:
            self._check("Output shape test", False, str(e))

    def test_output_values(self, session: ort.InferenceSession):
        """Test 4: Output values are valid probabilities."""
        print("\n[Test 4] Output Values")
        try:
            dummy = np.random.randn(10, self.input_size).astype(np.float32)
            raw_output = session.run(["output"], {"input": dummy})[0]

            # Apply softmax manually
            exp_out = np.exp(raw_output - raw_output.max(axis=1, keepdims=True))
            probs = exp_out / exp_out.sum(axis=1, keepdims=True)

            self._check(
                "All probabilities >= 0",
                bool(np.all(probs >= 0))
            )
            self._check(
                "All probabilities <= 1",
                bool(np.all(probs <= 1))
            )
            self._check(
                "Probabilities sum to 1.0",
                bool(np.allclose(probs.sum(axis=1), 1.0, atol=1e-5))
            )
            self._check(
                "No NaN values in output",
                bool(not np.any(np.isnan(raw_output)))
            )
            self._check(
                "No Inf values in output",
                bool(not np.any(np.isinf(raw_output)))
            )

        except Exception as e:
            self._check("Output values test", False, str(e))

    def test_inference_speed(self, session: ort.InferenceSession):
        """Test 5: Inference runs within 100ms."""
        print("\n[Test 5] Inference Speed")
        try:
            dummy = np.random.randn(1, self.input_size).astype(np.float32)

            # Warmup
            for _ in range(5):
                session.run(["output"], {"input": dummy})

            # Benchmark
            times = []
            for _ in range(100):
                start = time.perf_counter()
                session.run(["output"], {"input": dummy})
                end = time.perf_counter()
                times.append((end - start) * 1000)

            avg_ms = np.mean(times)
            p95_ms = np.percentile(times, 95)
            min_ms = np.min(times)

            self.logger.info(f"Avg inference: {avg_ms:.2f}ms")
            self.logger.info(f"P95 inference: {p95_ms:.2f}ms")
            self.logger.info(f"Min inference: {min_ms:.2f}ms")

            print(f"    Average: {avg_ms:.2f}ms")
            print(f"    P95:     {p95_ms:.2f}ms")
            print(f"    Min:     {min_ms:.2f}ms")

            self._check(
                "Average inference < 100ms",
                avg_ms < 100,
                f"Got: {avg_ms:.2f}ms"
            )
            self._check(
                "P95 inference < 200ms",
                p95_ms < 200,
                f"Got: {p95_ms:.2f}ms"
            )

        except Exception as e:
            self._check("Inference speed test", False, str(e))

    def test_pytorch_match(self, session: ort.InferenceSession):
        """Test 6: ONNX output matches PyTorch output."""
        print("\n[Test 6] PyTorch vs ONNX Match")

        if not self.checkpoint_path or not os.path.exists(self.checkpoint_path):
            print("    Skipped (no checkpoint provided)")
            return

        try:
            checkpoint = torch.load(
                self.checkpoint_path, map_location="cpu"
            )
            config = checkpoint.get("config", {})
            cfg = config.get("model", {})

            model_type = cfg.get("type", "cnn")
            if model_type == "cnn":
                model = CNNModel(
                    input_size=cfg.get("input_size", 512),
                    num_classes=2,
                    dropout=0.0,
                )
            else:
                model = MLPModel(
                    input_size=cfg.get("input_size", 512),
                    hidden_size=cfg.get("hidden_size", 256),
                    num_classes=2,
                    dropout=0.0,
                )

            model.load_state_dict(checkpoint["model_state_dict"])
            model.eval()

            # Run both
            test_input = np.random.randn(5, self.input_size).astype(np.float32)
            torch_input = torch.from_numpy(test_input)

            with torch.no_grad():
                torch_output = model(torch_input).numpy()

            onnx_output = session.run(["output"], {"input": test_input})[0]

            max_diff = np.max(np.abs(torch_output - onnx_output))
            self.logger.info(f"Max output difference: {max_diff:.8f}")

            self._check(
                "ONNX matches PyTorch output",
                max_diff < 1e-4,
                f"Max diff: {max_diff:.8f}"
            )

        except Exception as e:
            self._check("PyTorch match test", False, str(e))

    def test_edge_cases(self, session: ort.InferenceSession):
        """Test 7: Handle edge case inputs."""
        print("\n[Test 7] Edge Cases")
        try:
            # All zeros
            zeros = np.zeros((1, self.input_size), dtype=np.float32)
            out = session.run(["output"], {"input": zeros})[0]
            self._check(
                "Handles all-zero input",
                out is not None and not np.any(np.isnan(out))
            )

            # All ones
            ones = np.ones((1, self.input_size), dtype=np.float32)
            out = session.run(["output"], {"input": ones})[0]
            self._check(
                "Handles all-ones input",
                out is not None and not np.any(np.isnan(out))
            )

            # Large values
            large = np.full((1, self.input_size), 255.0, dtype=np.float32)
            out = session.run(["output"], {"input": large})[0]
            self._check(
                "Handles large byte values (255.0)",
                out is not None and not np.any(np.isnan(out))
            )

        except Exception as e:
            self._check("Edge cases test", False, str(e))

    def run_all(self):
        """Run all verification tests."""
        print("\n" + "=" * 60)
        print("SHADOW BRAIN ONNX VERIFICATION")
        print("=" * 60)
        print(f"Model: {self.onnx_path}")
        print(f"Size:  {os.path.getsize(self.onnx_path) / 1024 / 1024:.2f} MB")

        # Run tests
        if not self.test_model_loads():
            print("\nABORTED: Model failed to load")
            return False

        session = self.test_inference_session()
        if session is None:
            print("\nABORTED: Could not create inference session")
            return False

        self.test_output_shape(session)
        self.test_output_values(session)
        self.test_inference_speed(session)
        self.test_pytorch_match(session)
        self.test_edge_cases(session)

        # Summary
        total = self.passed + self.failed
        print("\n" + "=" * 60)
        print(f"RESULTS: {self.passed}/{total} tests passed")
        if self.failed == 0:
            print("✅ ALL TESTS PASSED - Model ready for deployment!")
        else:
            print(f"❌ {self.failed} test(s) failed - Check logs")
        print("=" * 60)

        return self.failed == 0


# ─────────────────────────────────────────
# CLI ENTRY POINT
# ─────────────────────────────────────────

def parse_args():
    parser = argparse.ArgumentParser(
        description="Verify exported ONNX model"
    )
    parser.add_argument(
        "--model",
        type=str,
        default="outputs/exported/shadow_brain.onnx",
        help="Path to ONNX model file"
    )
    parser.add_argument(
        "--checkpoint",
        type=str,
        default="outputs/checkpoints/best_model.pt",
        help="Path to PyTorch checkpoint for comparison"
    )
    return parser.parse_args()


def main():
    args = parse_args()

    if not os.path.exists(args.model):
        print(f"ERROR: ONNX model not found: {args.model}")
        print("Run export_onnx.py first.")
        sys.exit(1)

    verifier = ONNXVerifier(
        onnx_path=args.model,
        checkpoint_path=args.checkpoint,
    )
    success = verifier.run_all()
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
