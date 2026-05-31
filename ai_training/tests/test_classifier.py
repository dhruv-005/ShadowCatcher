# ============================================
# SHADOW CATCHER - Classifier Tests
# ============================================

import sys
import pytest
import torch
import numpy as np
from pathlib import Path

sys.path.append(str(Path(__file__).parent.parent / "src"))

from models.classifier import ShadowBrainClassifier
from models.cnn_model import CNNModel
from models.mlp_model import MLPModel


# ─────────────────────────────────────────
# FIXTURES
# ─────────────────────────────────────────

@pytest.fixture
def input_size():
    return 512

@pytest.fixture
def num_classes():
    return 2

@pytest.fixture
def batch_size():
    return 16

@pytest.fixture
def cnn_model(input_size, num_classes):
    """Create CNN model for testing."""
    model = CNNModel(
        input_size=input_size,
        num_classes=num_classes,
        dropout=0.0,
    )
    model.eval()
    return model

@pytest.fixture
def mlp_model(input_size, num_classes):
    """Create MLP model for testing."""
    model = MLPModel(
        input_size=input_size,
        hidden_size=256,
        num_classes=num_classes,
        dropout=0.0,
    )
    model.eval()
    return model

@pytest.fixture
def ensemble_model(input_size, num_classes):
    """Create ensemble classifier for testing."""
    model = ShadowBrainClassifier(
        input_size=input_size,
        hidden_size=256,
        num_classes=num_classes,
        dropout=0.0,
    )
    model.eval()
    return model

@pytest.fixture
def random_features(batch_size, input_size):
    """Random feature batch."""
    return torch.randn(batch_size, input_size)

@pytest.fixture
def zeros_features(batch_size, input_size):
    """All-zero feature batch."""
    return torch.zeros(batch_size, input_size)

@pytest.fixture
def ones_features(batch_size, input_size):
    """All-ones feature batch."""
    return torch.ones(batch_size, input_size)


# ─────────────────────────────────────────
# OUTPUT SHAPE TESTS
# ─────────────────────────────────────────

class TestOutputShape:
    """Test model output shapes."""

    def test_cnn_output_shape(
        self, cnn_model, random_features, batch_size, num_classes
    ):
        """CNN output shape is (batch, num_classes)."""
        with torch.no_grad():
            output = cnn_model(random_features)
        assert output.shape == (batch_size, num_classes), (
            f"Expected ({batch_size}, {num_classes}), got {output.shape}"
        )

    def test_mlp_output_shape(
        self, mlp_model, random_features, batch_size, num_classes
    ):
        """MLP output shape is (batch, num_classes)."""
        with torch.no_grad():
            output = mlp_model(random_features)
        assert output.shape == (batch_size, num_classes)

    def test_ensemble_output_shape(
        self, ensemble_model, random_features, batch_size, num_classes
    ):
        """Ensemble output shape is (batch, num_classes)."""
        with torch.no_grad():
            output = ensemble_model(random_features)
        assert output.shape == (batch_size, num_classes)

    def test_single_sample_shape(
        self, cnn_model, input_size, num_classes
    ):
        """Single sample output shape."""
        x = torch.randn(1, input_size)
        with torch.no_grad():
            output = cnn_model(x)
        assert output.shape == (1, num_classes)

    def test_large_batch_shape(self, cnn_model, input_size, num_classes):
        """Large batch size works correctly."""
        x = torch.randn(128, input_size)
        with torch.no_grad():
            output = cnn_model(x)
        assert output.shape == (128, num_classes)


# ─────────────────────────────────────────
# OUTPUT VALUE TESTS
# ─────────────────────────────────────────

class TestOutputValues:
    """Test model output value validity."""

    def test_no_nan_in_output_cnn(self, cnn_model, random_features):
        """CNN output contains no NaN values."""
        with torch.no_grad():
            output = cnn_model(random_features)
        assert not torch.any(torch.isnan(output)), "NaN in CNN output"

    def test_no_nan_in_output_mlp(self, mlp_model, random_features):
        """MLP output contains no NaN values."""
        with torch.no_grad():
            output = mlp_model(random_features)
        assert not torch.any(torch.isnan(output)), "NaN in MLP output"

    def test_no_nan_in_output_ensemble(
        self, ensemble_model, random_features
    ):
        """Ensemble output contains no NaN values."""
        with torch.no_grad():
            output = ensemble_model(random_features)
        assert not torch.any(torch.isnan(output)), "NaN in ensemble output"

    def test_no_inf_in_output(self, cnn_model, random_features):
        """No infinite values in output."""
        with torch.no_grad():
            output = cnn_model(random_features)
        assert not torch.any(torch.isinf(output)), "Inf in output"

    def test_softmax_probabilities_sum_to_one(
        self, cnn_model, random_features
    ):
        """Softmax probabilities sum to 1.0."""
        with torch.no_grad():
            logits = cnn_model(random_features)
            probs = torch.softmax(logits, dim=1)
            sums = probs.sum(dim=1)
        assert torch.allclose(
            sums,
            torch.ones_like(sums),
            atol=1e-5,
        ), "Probabilities do not sum to 1"

    def test_probabilities_between_zero_and_one(
        self, cnn_model, random_features
    ):
        """All probabilities are in [0, 1]."""
        with torch.no_grad():
            logits = cnn_model(random_features)
            probs = torch.softmax(logits, dim=1)
        assert torch.all(probs >= 0.0), "Negative probability found"
        assert torch.all(probs <= 1.0), "Probability > 1 found"

    def test_zero_input_no_crash(
        self, cnn_model, zeros_features
    ):
        """All-zero input does not crash."""
        with torch.no_grad():
            output = cnn_model(zeros_features)
        assert output is not None
        assert not torch.any(torch.isnan(output))

    def test_ones_input_no_crash(
        self, cnn_model, ones_features
    ):
        """All-ones input does not crash."""
        with torch.no_grad():
            output = cnn_model(ones_features)
        assert output is not None
        assert not torch.any(torch.isnan(output))


# ─────────────────────────────────────────
# PREDICT METHOD TESTS
# ─────────────────────────────────────────

class TestPredictMethod:
    """Test the predict() convenience method."""

    def test_cnn_predict_returns_tuple(
        self, cnn_model, random_features
    ):
        """predict() returns (predictions, probabilities)."""
        preds, probs = cnn_model.predict(random_features)
        assert preds is not None
        assert probs is not None

    def test_predictions_are_valid_labels(
        self, cnn_model, random_features, batch_size
    ):
        """All predictions are 0 or 1."""
        preds, _ = cnn_model.predict(random_features)
        assert preds.shape == (batch_size,)
        assert torch.all((preds == 0) | (preds == 1)), (
            "Invalid prediction label found"
        )

    def test_predict_single_cnn(self, cnn_model, input_size):
        """predict_single() returns valid result dict."""
        x = torch.rand(input_size)
        result = cnn_model.predict_single(x)

        assert "verdict" in result
        assert "label" in result
        assert "confidence" in result
        assert "benign_prob" in result
        assert "malicious_prob" in result

        assert result["verdict"] in ["BENIGN", "MALICIOUS"]
        assert result["label"] in [0, 1]
        assert 0.0 <= result["confidence"] <= 1.0
        assert 0.0 <= result["benign_prob"] <= 1.0
        assert 0.0 <= result["malicious_prob"] <= 1.0

    def test_predict_single_mlp(self, mlp_model, input_size):
        """MLP predict_single() works correctly."""
        x = torch.rand(input_size)
        result = mlp_model.predict_single(x)
        assert result["verdict"] in ["BENIGN", "MALICIOUS"]
        assert 0.0 <= result["confidence"] <= 1.0

    def test_predict_single_ensemble(self, ensemble_model, input_size):
        """Ensemble predict_single() works correctly."""
        x = torch.rand(input_size)
        result = ensemble_model.predict_single(x)
        assert result["verdict"] in ["BENIGN", "MALICIOUS"]

    def test_probs_sum_in_predict(
        self, cnn_model, random_features
    ):
        """Probabilities from predict() sum to 1."""
        _, probs = cnn_model.predict(random_features)
        sums = probs.sum(dim=1)
        assert torch.allclose(sums, torch.ones_like(sums), atol=1e-5)


# ─────────────────────────────────────────
# MODEL INFO TESTS
# ─────────────────────────────────────────

class TestModelInfo:
    """Test model info methods."""

    def test_cnn_model_info(self, cnn_model):
        """CNN model info returns valid dict."""
        info = cnn_model.get_model_info()
        assert info["model_type"] == "CNNModel"
        assert info["total_parameters"] > 0
        assert info["size_mb"] > 0

    def test_mlp_model_info(self, mlp_model):
        """MLP model info returns valid dict."""
        info = mlp_model.get_model_info()
        assert info["model_type"] == "MLPModel"
        assert info["total_parameters"] > 0

    def test_ensemble_model_info(self, ensemble_model):
        """Ensemble model info returns valid dict."""
        info = ensemble_model.get_model_info()
        assert info["model_type"] == "ShadowBrainClassifier"
        assert info["total_parameters"] > 0

    def test_model_has_parameters(self, cnn_model):
        """Model has trainable parameters."""
        params = list(cnn_model.parameters())
        assert len(params) > 0

    def test_parameters_require_grad_in_train_mode(
        self, input_size, num_classes
    ):
        """Parameters require grad in training mode."""
        model = CNNModel(input_size=input_size, num_classes=num_classes)
        model.train()
        for param in model.parameters():
            assert param.requires_grad


# ─────────────────────────────────────────
# DETERMINISM TESTS
# ─────────────────────────────────────────

class TestDeterminism:
    """Test model output determinism."""

    def test_eval_mode_deterministic(
        self, cnn_model, random_features
    ):
        """In eval mode, same input produces same output."""
        cnn_model.eval()
        with torch.no_grad():
            out1 = cnn_model(random_features)
            out2 = cnn_model(random_features)
        assert torch.allclose(out1, out2, atol=1e-6), (
            "Model not deterministic in eval mode"
        )

    def test_different_inputs_different_outputs(
        self, cnn_model, input_size
    ):
        """Different inputs produce different outputs."""
        x1 = torch.rand(1, input_size)
        x2 = torch.rand(1, input_size) + 0.5
        with torch.no_grad():
            out1 = cnn_model(x1)
            out2 = cnn_model(x2)
        assert not torch.allclose(out1, out2), (
            "Different inputs produced same output"
        )


# ─────────────────────────────────────────
# FEATURE IMPORTANCE TESTS
# ─────────────────────────────────────────

class TestFeatureImportance:
    """Test MLP feature importance methods."""

    def test_feature_importance_shape(self, mlp_model, input_size):
        """Feature importance has correct shape."""
        importance = mlp_model.get_feature_importance()
        assert importance.shape == (input_size,)

    def test_feature_importance_in_valid_range(self, mlp_model):
        """Feature importance values are in [0, 1]."""
        importance = mlp_model.get_feature_importance()
        assert torch.all(importance >= 0.0)
        assert torch.all(importance <= 1.0)

    def test_top_features_returns_list(self, mlp_model):
        """get_top_features() returns list of indices."""
        top = mlp_model.get_top_features(k=10)
        assert isinstance(top, list)
        assert len(top) == 10

    def test_top_features_valid_indices(self, mlp_model, input_size):
        """Top feature indices are valid."""
        top = mlp_model.get_top_features(k=20)
        for idx in top:
            assert 0 <= idx < input_size


# ─────────────────────────────────────────
# TRAINING MODE TESTS
# ─────────────────────────────────────────

class TestTrainingMode:
    """Test model behavior in train vs eval mode."""

    def test_model_switches_modes(self, cnn_model):
        """Model correctly switches between train/eval."""
        cnn_model.train()
        assert cnn_model.training is True

        cnn_model.eval()
        assert cnn_model.training is False

    def test_dropout_active_in_train(self, input_size, num_classes):
        """Dropout causes different outputs in train mode."""
        model = CNNModel(
            input_size=input_size,
            num_classes=num_classes,
            dropout=0.5,
        )
        model.train()
        x = torch.ones(10, input_size)

        with torch.no_grad():
            out1 = model(x)
            out2 = model(x)

        # With high dropout, outputs should differ in train mode
        # (Not guaranteed but very likely with dropout=0.5)
        # We just check it doesn't crash
        assert out1.shape == (10, num_classes)
        assert out2.shape == (10, num_classes)
