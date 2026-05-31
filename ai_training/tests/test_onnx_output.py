# ============================================
# SHADOW CATCHER - ONNX Output Tests
# ============================================

import sys
import os
import pytest
import numpy as np
import torch
import tempfile
from pathlib import Path

sys.path.append(str(Path(__file__).parent.parent / "src"))

from models.cnn_model import CNNModel
from models.mlp_model import MLPModel

# Skip if onnxruntime not installed
onnxruntime = pytest.importorskip(
    "onnxruntime",
    reason="onnxruntime not installed"
)
onnx = pytest.importorskip(
    "onnx",
    reason="onnx not installed"
)


# ─────────────────────────────────────────
# FIXTURES
# ─────────────────────────────────────────

@pytest.fixture(scope="module")
def input_size():
    return 512

@pytest.fixture(scope="module")
def num_classes():
    return 2

@pytest.fixture(scope="module")
def cnn_onnx_path(input_size, num_classes, tmp_path_factory):
    """Export CNN model to ONNX and return path."""
    tmp_path = tmp_path_factory.mktemp("onnx")
    onnx_path = str(tmp_path / "cnn_test.onnx")

    model = CNNModel(
        input_size=input_size,
        num_classes=num_classes,
        dropout=0.0,
    )
    model.eval()

    dummy = torch.randn(1, input_size)
    torch.onnx.export(
        model,
        dummy,
        onnx_path,
        opset_version=17,
        input_names=["input"],
        output_names=["output"],
        dynamic_axes={
            "input":  {0: "batch_size"},
            "output": {0: "batch_size"},
        },
        do_constant_folding=True,
        verbose=False,
    )
    return onnx_path, model

@pytest.fixture(scope="module")
def mlp_onnx_path(input_size, num_classes, tmp_path_factory):
    """Export MLP model to ONNX and return path."""
    tmp_path = tmp_path_factory.mktemp("onnx_mlp")
    onnx_path = str(tmp_path / "mlp_test.onnx")

    model = MLPModel(
        input_size=input_size,
        hidden_size=128,
        num_classes=num_classes,
        dropout=0.0,
    )
    model.eval()

    dummy = torch.randn(1, input_size)
    torch.onnx.export(
        model,
        dummy,
        onnx_path,
        opset_version=17,
        input_names=["input"],
        output_names=["output"],
        dynamic_axes={
            "input":  {0: "batch_size"},
            "output": {0: "batch_size"},
        },
        verbose=False,
    )
    return onnx_path, model

@pytest.fixture(scope="module")
def cnn_session(cnn_onnx_path):
    """Create ORT inference session for CNN."""
    onnx_path, model = cnn_onnx_path
    session = onnxruntime.InferenceSession(
        onnx_path,
        providers=["CPUExecutionProvider"],
    )
    return session, model

@pytest.fixture(scope="module")
def mlp_session(mlp_onnx_path):
    """Create ORT inference session for MLP."""
    onnx_path, model = mlp_onnx_path
    session = onnxruntime.InferenceSession(
        onnx_path,
        providers=["CPUExecutionProvider"],
    )
    return session, model


# ─────────────────────────────────────────
# ONNX MODEL VALIDITY TESTS
# ─────────────────────────────────────────

class TestONNXModelValidity:
    """Test that exported ONNX models are valid."""

    def test_cnn_onnx_file_exists(self, cnn_onnx_path):
        """ONNX file was created."""
        onnx_path, _ = cnn_onnx_path
        assert os.path.exists(onnx_path), "ONNX file not created"

    def test_cnn_onnx_file_not_empty(self, cnn_onnx_path):
        """ONNX file is not empty."""
        onnx_path, _ = cnn_onnx_path
        assert os.path.getsize(onnx_path) > 1000, "ONNX file too small"

    def test_cnn_onnx_loads(self, cnn_onnx_path):
        """ONNX model loads without error."""
        onnx_path, _ = cnn_onnx_path
        model = onnx.load(onnx_path)
        assert model is not None

    def test_cnn_onnx_passes_checker(self, cnn_onnx_path):
        """ONNX model passes built-in checker."""
        onnx_path, _ = cnn_onnx_path
        model = onnx.load(onnx_path)
        try:
            onnx.checker.check_model(model)
        except onnx.checker.ValidationError as e:
            pytest.fail(f"ONNX validation failed: {e}")

    def test_mlp_onnx_passes_checker(self, mlp_onnx_path):
        """MLP ONNX model passes checker."""
        onnx_path, _ = mlp_onnx_path
        model = onnx.load(onnx_path)
        try:
            onnx.checker.check_model(model)
        except onnx.checker.ValidationError as e:
            pytest.fail(f"MLP ONNX validation failed: {e}")

    def test_onnx_has_input_node(self, cnn_onnx_path):
        """ONNX model has input named 'input'."""
        onnx_path, _ = cnn_onnx_path
        model = onnx.load(onnx_path)
        input_names = [inp.name for inp in model.graph.input]
        assert "input" in input_names, (
            f"'input' not found in: {input_names}"
        )

    def test_onnx_has_output_node(self, cnn_onnx_path):
        """ONNX model has output named 'output'."""
        onnx_path, _ = cnn_onnx_path
        model = onnx.load(onnx_path)
        output_names = [out.name for out in model.graph.output]
        assert "output" in output_names, (
            f"'output' not found in: {output_names}"
        )


# ─────────────────────────────────────────
# ORT SESSION TESTS
# ─────────────────────────────────────────

class TestORTSession:
    """Test ONNX Runtime inference session."""

    def test_session_creates_successfully(self, cnn_session):
        """ORT session is created without error."""
        session, _ = cnn_session
        assert session is not None

    def test_session_input_name(self, cnn_session):
        """Session input is named 'input'."""
        session, _ = cnn_session
        input_name = session.get_inputs()[0].name
        assert input_name == "input"

    def test_session_output_name(self, cnn_session):
        """Session output is named 'output'."""
        session, _ = cnn_session
        output_name = session.get_outputs()[0].name
        assert output_name == "output"

    def test_session_input_type(self, cnn_session):
        """Session input type is float tensor."""
        session, _ = cnn_session
        input_type = session.get_inputs()[0].type
        assert "float" in input_type.lower()

    def test_mlp_session_creates_successfully(self, mlp_session):
        """MLP ORT session creates successfully."""
        session, _ = mlp_session
        assert session is not None


# ─────────────────────────────────────────
# INFERENCE OUTPUT TESTS
# ─────────────────────────────────────────

class TestONNXInference:
    """Test ONNX model inference output."""

    def test_single_sample_inference(
        self, cnn_session, input_size, num_classes
    ):
        """Single sample inference returns correct shape."""
        session, _ = cnn_session
        x = np.random.randn(1, input_size).astype(np.float32)
        output = session.run(["output"], {"input": x})[0]
        assert output.shape == (1, num_classes), (
            f"Expected (1, {num_classes}), got {output.shape}"
        )

    def test_batch_inference(
        self, cnn_session, input_size, num_classes
    ):
        """Batch inference returns correct shape."""
        session, _ = cnn_session
        x = np.random.randn(32, input_size).astype(np.float32)
        output = session.run(["output"], {"input": x})[0]
        assert output.shape == (32, num_classes)

    def test_no_nan_in_onnx_output(self, cnn_session, input_size):
        """No NaN values in ONNX output."""
        session, _ = cnn_session
        x = np.random.randn(10, input_size).astype(np.float32)
        output = session.run(["output"], {"input": x})[0]
        assert not np.any(np.isnan(output)), "NaN in ONNX output"

    def test_no_inf_in_onnx_output(self, cnn_session, input_size):
        """No Inf values in ONNX output."""
        session, _ = cnn_session
        x = np.random.randn(10, input_size).astype(np.float32)
        output = session.run(["output"], {"input": x})[0]
        assert not np.any(np.isinf(output)), "Inf in ONNX output"

    def test_softmax_sums_to_one(
        self, cnn_session, input_size
    ):
        """ONNX softmax output sums to 1."""
        session, _ = cnn_session
        x = np.random.randn(10, input_size).astype(np.float32)
        logits = session.run(["output"], {"input": x})[0]

        # Apply softmax manually
        exp_out = np.exp(logits - logits.max(axis=1, keepdims=True))
        probs = exp_out / exp_out.sum(axis=1, keepdims=True)

        sums = probs.sum(axis=1)
        np.testing.assert_allclose(
            sums,
            np.ones(10),
            atol=1e-5,
            err_msg="Probabilities do not sum to 1",
        )

    def test_zero_input_inference(
        self, cnn_session, input_size, num_classes
    ):
        """All-zero input produces valid output."""
        session, _ = cnn_session
        x = np.zeros((1, input_size), dtype=np.float32)
        output = session.run(["output"], {"input": x})[0]
        assert output.shape == (1, num_classes)
        assert not np.any(np.isnan(output))

    def test_ones_input_inference(
        self, cnn_session, input_size, num_classes
    ):
        """All-ones input produces valid output."""
        session, _ = cnn_session
        x = np.ones((1, input_size), dtype=np.float32)
        output = session.run(["output"], {"input": x})[0]
        assert output.shape == (1, num_classes)
        assert not np.any(np.isnan(output))


# ─────────────────────────────────────────
# PYTORCH vs ONNX MATCH TESTS
# ─────────────────────────────────────────

class TestPyTorchONNXMatch:
    """Test that ONNX output matches PyTorch output."""

    def test_cnn_outputs_match(
        self, cnn_session, input_size
    ):
        """CNN ONNX output matches PyTorch output."""
        session, model = cnn_session
        model.eval()

        x_np = np.random.randn(5, input_size).astype(np.float32)
        x_torch = torch.from_numpy(x_np)

        with torch.no_grad():
            torch_out = model(x_torch).numpy()

        onnx_out = session.run(["output"], {"input": x_np})[0]

        max_diff = np.max(np.abs(torch_out - onnx_out))
        assert max_diff < 1e-4, (
            f"PyTorch vs ONNX max diff too large: {max_diff:.6f}"
        )

    def test_mlp_outputs_match(
        self, mlp_session, input_size
    ):
        """MLP ONNX output matches PyTorch output."""
        session, model = mlp_session
        model.eval()

        x_np = np.random.randn(5, input_size).astype(np.float32)
        x_torch = torch.from_numpy(x_np)

        with torch.no_grad():
            torch_out = model(x_torch).numpy()

        onnx_out = session.run(["output"], {"input": x_np})[0]

        max_diff = np.max(np.abs(torch_out - onnx_out))
        assert max_diff < 1e-4, (
            f"MLP PyTorch vs ONNX max diff: {max_diff:.6f}"
        )

    def test_predictions_match(
        self, cnn_session, input_size
    ):
        """Predicted class indices match between PyTorch and ONNX."""
        session, model = cnn_session
        model.eval()

        x_np = np.random.randn(20, input_size).astype(np.float32)
        x_torch = torch.from_numpy(x_np)

        with torch.no_grad():
            torch_logits = model(x_torch).numpy()
        torch_preds = np.argmax(torch_logits, axis=1)

        onnx_logits = session.run(["output"], {"input": x_np})[0]
        onnx_preds = np.argmax(onnx_logits, axis=1)

        match_rate = np.mean(torch_preds == onnx_preds)
        assert match_rate == 1.0, (
            f"Prediction mismatch: {match_rate:.2%} agreement"
        )


# ─────────────────────────────────────────
# PERFORMANCE TESTS
# ─────────────────────────────────────────

class TestONNXPerformance:
    """Test ONNX inference performance."""

    def test_inference_under_100ms(
        self, cnn_session, input_size
    ):
        """Single inference completes in < 100ms."""
        import time
        session, _ = cnn_session
        x = np.random.randn(1, input_size).astype(np.float32)

        # Warmup
        for _ in range(5):
            session.run(["output"], {"input": x})

        # Benchmark
        times = []
        for _ in range(50):
            start = time.perf_counter()
            session.run(["output"], {"input": x})
            end = time.perf_counter()
            times.append((end - start) * 1000)

        avg_ms = np.mean(times)
        assert avg_ms < 100, (
            f"ONNX inference too slow: {avg_ms:.2f}ms"
        )

    def test_batch_throughput(
        self, cnn_session, input_size
    ):
        """Batch of 64 samples completes in < 500ms."""
        import time
        session, _ = cnn_session
        x = np.random.randn(64, input_size).astype(np.float32)

        start = time.perf_counter()
        for _ in range(10):
            session.run(["output"], {"input": x})
        elapsed = (time.perf_counter() - start) * 1000 / 10

        assert elapsed < 500, (
            f"Batch throughput too slow: {elapsed:.2f}ms for 64 samples"
        )
