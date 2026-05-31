# ============================================
# SHADOW CATCHER - MLP Model
# Multi-Layer Perceptron for feature classification
# ============================================

import torch
import torch.nn as nn
import torch.nn.functional as F
from typing import Tuple, List, Optional


# ─────────────────────────────────────────
# MLP BLOCK
# ─────────────────────────────────────────

class MLPBlock(nn.Module):
    """
    Single MLP block:
    Linear → LayerNorm → GELU → Dropout
    with optional residual connection.
    """

    def __init__(
        self,
        in_size: int,
        out_size: int,
        dropout: float = 0.3,
        use_residual: bool = True,
    ):
        super().__init__()
        self.use_residual = use_residual and (in_size == out_size)

        self.block = nn.Sequential(
            nn.Linear(in_size, out_size),
            nn.LayerNorm(out_size),
            nn.GELU(),
            nn.Dropout(dropout),
        )

        if use_residual and in_size != out_size:
            self.residual_proj = nn.Linear(in_size, out_size)
        else:
            self.residual_proj = None

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        out = self.block(x)
        if self.use_residual:
            if self.residual_proj is not None:
                x = self.residual_proj(x)
            out = out + x
        return out


# ─────────────────────────────────────────
# GATED LINEAR UNIT
# ─────────────────────────────────────────

class GLULayer(nn.Module):
    """
    Gated Linear Unit layer.
    output = sigmoid(Wx + b) * (Vx + c)
    Better at learning feature selection.
    """

    def __init__(self, in_size: int, out_size: int):
        super().__init__()
        self.gate = nn.Linear(in_size, out_size)
        self.transform = nn.Linear(in_size, out_size)
        self.norm = nn.LayerNorm(out_size)

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        gate = torch.sigmoid(self.gate(x))
        transform = self.transform(x)
        out = gate * transform
        return self.norm(out)


# ─────────────────────────────────────────
# FEATURE SELECTOR
# ─────────────────────────────────────────

class FeatureSelector(nn.Module):
    """
    Soft feature selection using learned weights.
    Learns which of the 512 input features matter most.
    """

    def __init__(self, feature_size: int, temperature: float = 1.0):
        super().__init__()
        self.temperature = temperature
        self.selector_weights = nn.Parameter(
            torch.ones(feature_size)
        )

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        weights = torch.sigmoid(
            self.selector_weights / self.temperature
        )
        return x * weights

    def get_top_features(self, k: int = 50) -> torch.Tensor:
        """Return indices of top-k most important features."""
        weights = torch.sigmoid(
            self.selector_weights / self.temperature
        )
        return torch.topk(weights, k).indices


# ─────────────────────────────────────────
# MLP MODEL
# ─────────────────────────────────────────

class MLPModel(nn.Module):
    """
    Multi-Layer Perceptron for malware classification.

    Architecture:
    Input (512)
      → Feature Selector
      → GLU Layer
      → MLP Blocks with residual connections
      → Classification Head
      → Output (2)

    Best for: Statistical and metadata features.
    Faster inference than CNN.
    """

    def __init__(
        self,
        input_size: int = 512,
        hidden_size: int = 256,
        num_classes: int = 2,
        dropout: float = 0.3,
        num_layers: int = 6,
        layer_sizes: Optional[List[int]] = None,
    ):
        super().__init__()

        self.input_size = input_size
        self.hidden_size = hidden_size
        self.num_classes = num_classes
        self.dropout_rate = dropout

        # Default layer sizes if not specified
        if layer_sizes is None:
            layer_sizes = [
                input_size,
                hidden_size * 4,   # 1024
                hidden_size * 2,   # 512
                hidden_size,       # 256
                hidden_size // 2,  # 128
                hidden_size // 4,  # 64
            ]

        # ── Feature Selector ──
        self.feature_selector = FeatureSelector(input_size)

        # ── Input Normalization ──
        self.input_norm = nn.LayerNorm(input_size)

        # ── GLU Entry Layer ──
        self.glu_entry = GLULayer(input_size, layer_sizes[1])

        # ── MLP Backbone ──
        self.mlp_blocks = nn.ModuleList()
        for i in range(1, len(layer_sizes) - 1):
            block = MLPBlock(
                in_size=layer_sizes[i],
                out_size=layer_sizes[i + 1],
                dropout=dropout,
                use_residual=True,
            )
            self.mlp_blocks.append(block)

        # ── GLU Exit Layer ──
        final_size = layer_sizes[-1]
        self.glu_exit = GLULayer(final_size, hidden_size // 4)

        # ── Classification Head ──
        head_in = hidden_size // 4
        self.classifier = nn.Sequential(
            nn.Linear(head_in, head_in // 2),
            nn.GELU(),
            nn.Dropout(dropout * 0.5),
            nn.Linear(head_in // 2, num_classes),
        )

        # ── Auxiliary Head (for deep supervision) ──
        mid_size = layer_sizes[len(layer_sizes) // 2]
        self.aux_classifier = nn.Linear(mid_size, num_classes)
        self.mid_layer_idx = len(self.mlp_blocks) // 2

        self._init_weights()

    def _init_weights(self):
        """Initialize all linear layers."""
        for m in self.modules():
            if isinstance(m, nn.Linear):
                nn.init.kaiming_normal_(
                    m.weight,
                    mode="fan_in",
                    nonlinearity="relu",
                )
                if m.bias is not None:
                    nn.init.zeros_(m.bias)
            elif isinstance(m, nn.LayerNorm):
                nn.init.ones_(m.weight)
                nn.init.zeros_(m.bias)

    def forward(
        self,
        x: torch.Tensor,
        return_aux: bool = False,
    ) -> torch.Tensor:
        """
        Forward pass.

        Args:
            x: Input features (batch, input_size)
            return_aux: If True, also return auxiliary logits

        Returns:
            logits: (batch, num_classes)
            aux_logits (optional): (batch, num_classes)
        """
        # ── Feature Selection ──
        x = self.feature_selector(x)

        # ── Input Normalization ──
        x = self.input_norm(x)

        # ── GLU Entry ──
        x = self.glu_entry(x)

        # ── MLP Blocks ──
        aux_logits = None
        for i, block in enumerate(self.mlp_blocks):
            x = block(x)
            # Auxiliary classification at middle layer
            if return_aux and i == self.mid_layer_idx:
                aux_logits = self.aux_classifier(x)

        # ── GLU Exit ──
        x = self.glu_exit(x)

        # ── Classification ──
        logits = self.classifier(x)

        if return_aux and aux_logits is not None:
            return logits, aux_logits

        return logits

    def predict(
        self,
        x: torch.Tensor,
    ) -> Tuple[torch.Tensor, torch.Tensor]:
        """Get predictions and probabilities."""
        self.eval()
        with torch.no_grad():
            logits = self.forward(x)
            probs = F.softmax(logits, dim=1)
            preds = torch.argmax(probs, dim=1)
        return preds, probs

    def predict_single(self, features: torch.Tensor) -> dict:
        """
        Predict a single feature vector.

        Returns:
            dict with verdict, confidence, probabilities
        """
        self.eval()
        with torch.no_grad():
            logits = self.forward(features.unsqueeze(0))
            probs = F.softmax(logits, dim=1)[0]
            pred = torch.argmax(probs).item()
            confidence = probs[pred].item()

        return {
            "verdict": "MALICIOUS" if pred == 1 else "BENIGN",
            "label": pred,
            "confidence": confidence,
            "benign_prob": probs[0].item(),
            "malicious_prob": probs[1].item(),
        }

    def get_feature_importance(self) -> torch.Tensor:
        """
        Return feature importance scores from selector.
        Higher value = more important feature.
        """
        return torch.sigmoid(
            self.feature_selector.selector_weights /
            self.feature_selector.temperature
        ).detach()

    def get_top_features(self, k: int = 20) -> List[int]:
        """Return indices of top-k most important features."""
        importance = self.get_feature_importance()
        return torch.topk(importance, k).indices.tolist()

    def get_model_info(self) -> dict:
        """Return model info."""
        total = sum(p.numel() for p in self.parameters())
        trainable = sum(
            p.numel() for p in self.parameters() if p.requires_grad
        )
        return {
            "model_type": "MLPModel",
            "input_size": self.input_size,
            "hidden_size": self.hidden_size,
            "num_classes": self.num_classes,
            "num_mlp_blocks": len(self.mlp_blocks),
            "total_parameters": total,
            "trainable_parameters": trainable,
            "size_mb": round(total * 4 / 1024 / 1024, 2),
        }
