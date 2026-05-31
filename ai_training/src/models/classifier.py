# ============================================
# SHADOW CATCHER - Shadow Brain Classifier
# Ensemble model combining CNN + MLP
# ============================================

import torch
import torch.nn as nn
import torch.nn.functional as F
from typing import Tuple, Optional


# ─────────────────────────────────────────
# ATTENTION MECHANISM
# ─────────────────────────────────────────

class FeatureAttention(nn.Module):
    """
    Self-attention module to weight important features.
    Helps model focus on malware-relevant byte patterns.
    """

    def __init__(self, feature_size: int, num_heads: int = 8):
        super().__init__()
        self.feature_size = feature_size
        self.num_heads = num_heads
        head_dim = feature_size // num_heads

        self.query = nn.Linear(feature_size, feature_size)
        self.key = nn.Linear(feature_size, feature_size)
        self.value = nn.Linear(feature_size, feature_size)
        self.out_proj = nn.Linear(feature_size, feature_size)
        self.scale = head_dim ** -0.5
        self.norm = nn.LayerNorm(feature_size)

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        """
        Args:
            x: Input tensor of shape (batch, feature_size)
        Returns:
            Attended features of shape (batch, feature_size)
        """
        residual = x

        # Reshape for multi-head attention
        B = x.shape[0]
        x_2d = x.unsqueeze(1)  # (B, 1, feature_size)

        Q = self.query(x_2d)
        K = self.key(x_2d)
        V = self.value(x_2d)

        # Attention scores
        scores = torch.bmm(Q, K.transpose(1, 2)) * self.scale
        attn_weights = F.softmax(scores, dim=-1)

        # Apply attention
        attended = torch.bmm(attn_weights, V)
        attended = attended.squeeze(1)
        attended = self.out_proj(attended)

        # Residual connection + norm
        output = self.norm(attended + residual)
        return output


# ─────────────────────────────────────────
# RESIDUAL BLOCK
# ─────────────────────────────────────────

class ResidualBlock(nn.Module):
    """
    Residual block for deep feature processing.
    Prevents vanishing gradients in deep networks.
    """

    def __init__(self, size: int, dropout: float = 0.3):
        super().__init__()
        self.block = nn.Sequential(
            nn.Linear(size, size),
            nn.BatchNorm1d(size),
            nn.GELU(),
            nn.Dropout(dropout),
            nn.Linear(size, size),
            nn.BatchNorm1d(size),
        )
        self.activation = nn.GELU()
        self.dropout = nn.Dropout(dropout)

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        residual = x
        out = self.block(x)
        out = self.activation(out + residual)
        return self.dropout(out)


# ─────────────────────────────────────────
# SHADOW BRAIN CLASSIFIER (ENSEMBLE)
# ─────────────────────────────────────────

class ShadowBrainClassifier(nn.Module):
    """
    Main Shadow Brain ensemble classifier.

    Architecture:
    ┌─────────────────────────────────────┐
    │ Input Features (512)                │
    ├──────────────┬──────────────────────┤
    │ CNN Branch   │ MLP Branch           │
    │ (byte conv)  │ (statistical)        │
    ├──────────────┴──────────────────────┤
    │ Feature Attention                   │
    ├─────────────────────────────────────┤
    │ Fusion Layer                        │
    ├─────────────────────────────────────┤
    │ Residual Blocks                     │
    ├─────────────────────────────────────┤
    │ Output: [benign_prob, malicious_prob]│
    └─────────────────────────────────────┘
    """

    def __init__(
        self,
        input_size: int = 512,
        hidden_size: int = 256,
        num_classes: int = 2,
        dropout: float = 0.3,
        num_residual_blocks: int = 3,
    ):
        super().__init__()

        self.input_size = input_size
        self.hidden_size = hidden_size
        self.num_classes = num_classes

        # ── CNN Branch (processes header bytes) ──
        # Takes first 256 features (raw header bytes)
        self.cnn_branch = nn.Sequential(
            # Reshape to (batch, 1, 256) for Conv1d
            nn.Unflatten(1, (1, 256)) if input_size >= 256 else nn.Identity(),
        )
        self.cnn_conv = nn.Sequential(
            nn.Conv1d(1, 32, kernel_size=8, stride=2, padding=3),
            nn.BatchNorm1d(32),
            nn.GELU(),
            nn.Conv1d(32, 64, kernel_size=4, stride=2, padding=1),
            nn.BatchNorm1d(64),
            nn.GELU(),
            nn.Conv1d(64, 128, kernel_size=4, stride=2, padding=1),
            nn.BatchNorm1d(128),
            nn.GELU(),
            nn.AdaptiveAvgPool1d(4),
            nn.Flatten(),
        )
        cnn_output_size = 128 * 4  # 512

        self.cnn_proj = nn.Sequential(
            nn.Linear(cnn_output_size, hidden_size),
            nn.BatchNorm1d(hidden_size),
            nn.GELU(),
            nn.Dropout(dropout),
        )

        # ── MLP Branch (processes all features) ──
        self.mlp_branch = nn.Sequential(
            nn.Linear(input_size, hidden_size * 2),
            nn.BatchNorm1d(hidden_size * 2),
            nn.GELU(),
            nn.Dropout(dropout),
            nn.Linear(hidden_size * 2, hidden_size),
            nn.BatchNorm1d(hidden_size),
            nn.GELU(),
            nn.Dropout(dropout),
        )

        # ── Feature Attention ──
        fusion_size = hidden_size * 2  # CNN + MLP concatenated
        self.attention = FeatureAttention(
            feature_size=fusion_size,
            num_heads=8,
        )

        # ── Fusion Layer ──
        self.fusion = nn.Sequential(
            nn.Linear(fusion_size, hidden_size),
            nn.BatchNorm1d(hidden_size),
            nn.GELU(),
            nn.Dropout(dropout),
        )

        # ── Residual Blocks ──
        self.residual_blocks = nn.ModuleList([
            ResidualBlock(hidden_size, dropout)
            for _ in range(num_residual_blocks)
        ])

        # ── Classification Head ──
        self.classifier = nn.Sequential(
            nn.Linear(hidden_size, hidden_size // 2),
            nn.GELU(),
            nn.Dropout(dropout * 0.5),
            nn.Linear(hidden_size // 2, num_classes),
        )

        # ── Weight Initialization ──
        self._init_weights()

    def _init_weights(self):
        """Initialize weights using Kaiming initialization."""
        for module in self.modules():
            if isinstance(module, nn.Linear):
                nn.init.kaiming_normal_(
                    module.weight,
                    mode="fan_out",
                    nonlinearity="relu",
                )
                if module.bias is not None:
                    nn.init.zeros_(module.bias)
            elif isinstance(module, nn.Conv1d):
                nn.init.kaiming_normal_(
                    module.weight,
                    mode="fan_out",
                    nonlinearity="relu",
                )
            elif isinstance(module, nn.BatchNorm1d):
                nn.init.ones_(module.weight)
                nn.init.zeros_(module.bias)

    def forward(
        self,
        x: torch.Tensor,
        return_features: bool = False,
    ) -> torch.Tensor:
        """
        Forward pass.

        Args:
            x: Input features (batch, input_size)
            return_features: If True, return features before classifier

        Returns:
            Logits of shape (batch, num_classes)
        """
        # ── CNN Branch ──
        # Use only header bytes (first 256 features)
        header_bytes = x[:, :256]
        cnn_in = header_bytes.unsqueeze(1)  # (B, 1, 256)
        cnn_features = self.cnn_conv(cnn_in)
        cnn_out = self.cnn_proj(cnn_features)

        # ── MLP Branch ──
        mlp_out = self.mlp_branch(x)

        # ── Fusion ──
        fused = torch.cat([cnn_out, mlp_out], dim=1)

        # ── Attention ──
        attended = self.attention(fused)

        # ── Fusion Layer ──
        features = self.fusion(attended)

        # ── Residual Blocks ──
        for block in self.residual_blocks:
            features = block(features)

        if return_features:
            return features

        # ── Classification ──
        logits = self.classifier(features)
        return logits

    def predict(
        self,
        x: torch.Tensor,
    ) -> Tuple[torch.Tensor, torch.Tensor]:
        """
        Get class predictions and probabilities.

        Returns:
            predictions: Class indices (batch,)
            probabilities: Class probabilities (batch, num_classes)
        """
        self.eval()
        with torch.no_grad():
            logits = self.forward(x)
            probs = F.softmax(logits, dim=1)
            preds = torch.argmax(probs, dim=1)
        return preds, probs

    def predict_single(
        self,
        features: torch.Tensor,
    ) -> dict:
        """
        Predict a single sample.

        Returns:
            dict with verdict, confidence, probabilities
        """
        self.eval()
        with torch.no_grad():
            x = features.unsqueeze(0)
            logits = self.forward(x)
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

    def get_model_info(self) -> dict:
        """Return model architecture info."""
        total_params = sum(p.numel() for p in self.parameters())
        trainable_params = sum(
            p.numel() for p in self.parameters() if p.requires_grad
        )
        return {
            "model_type": "ShadowBrainClassifier",
            "input_size": self.input_size,
            "hidden_size": self.hidden_size,
            "num_classes": self.num_classes,
            "total_parameters": total_params,
            "trainable_parameters": trainable_params,
            "size_mb": total_params * 4 / (1024 * 1024),
        }
