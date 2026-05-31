# ============================================
# SHADOW CATCHER - CNN Model
# Convolutional Neural Network for byte analysis
# ============================================

import torch
import torch.nn as nn
import torch.nn.functional as F
from typing import Tuple, List


# ─────────────────────────────────────────
# CONV BLOCK
# ─────────────────────────────────────────

class ConvBlock(nn.Module):
    """
    Single convolutional block:
    Conv1d → BatchNorm → Activation → Dropout
    """

    def __init__(
        self,
        in_channels: int,
        out_channels: int,
        kernel_size: int = 3,
        stride: int = 1,
        padding: int = 1,
        dropout: float = 0.2,
    ):
        super().__init__()
        self.conv = nn.Conv1d(
            in_channels,
            out_channels,
            kernel_size=kernel_size,
            stride=stride,
            padding=padding,
            bias=False,
        )
        self.bn = nn.BatchNorm1d(out_channels)
        self.act = nn.GELU()
        self.drop = nn.Dropout(dropout)

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        return self.drop(self.act(self.bn(self.conv(x))))


# ─────────────────────────────────────────
# DEPTHWISE SEPARABLE CONV BLOCK
# ─────────────────────────────────────────

class DepthwiseSepConv(nn.Module):
    """
    Depthwise separable convolution.
    More efficient than standard Conv1d.
    """

    def __init__(
        self,
        in_channels: int,
        out_channels: int,
        kernel_size: int = 3,
    ):
        super().__init__()
        self.depthwise = nn.Conv1d(
            in_channels,
            in_channels,
            kernel_size=kernel_size,
            padding=kernel_size // 2,
            groups=in_channels,
            bias=False,
        )
        self.pointwise = nn.Conv1d(
            in_channels,
            out_channels,
            kernel_size=1,
            bias=False,
        )
        self.bn = nn.BatchNorm1d(out_channels)
        self.act = nn.GELU()

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        x = self.depthwise(x)
        x = self.pointwise(x)
        return self.act(self.bn(x))


# ─────────────────────────────────────────
# SQUEEZE AND EXCITATION BLOCK
# ─────────────────────────────────────────

class SEBlock(nn.Module):
    """
    Squeeze-and-Excitation block.
    Recalibrates channel features adaptively.
    """

    def __init__(self, channels: int, reduction: int = 16):
        super().__init__()
        reduced = max(channels // reduction, 4)
        self.se = nn.Sequential(
            nn.AdaptiveAvgPool1d(1),
            nn.Flatten(),
            nn.Linear(channels, reduced),
            nn.ReLU(),
            nn.Linear(reduced, channels),
            nn.Sigmoid(),
        )

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        # x shape: (batch, channels, length)
        scale = self.se(x).unsqueeze(-1)
        return x * scale


# ─────────────────────────────────────────
# CNN MODEL
# ─────────────────────────────────────────

class CNNModel(nn.Module):
    """
    Convolutional Neural Network for malware detection.

    Architecture:
    Input (512) → Reshape (1, 512) → Conv Layers → Global Pool → FC → Output

    The CNN treats the feature vector as a 1D signal
    and learns local patterns in byte sequences.

    Best for: Detecting patterns in raw header bytes.
    """

    def __init__(
        self,
        input_size: int = 512,
        num_classes: int = 2,
        dropout: float = 0.3,
        channels: List[int] = None,
    ):
        super().__init__()

        self.input_size = input_size
        self.num_classes = num_classes
        self.dropout_rate = dropout

        if channels is None:
            channels = [32, 64, 128, 256]

        # ── Input Projection ──
        # Project 1D feature vector to multi-channel representation
        self.input_proj = nn.Sequential(
            nn.Linear(input_size, input_size),
            nn.LayerNorm(input_size),
        )

        # ── Convolutional Backbone ──
        self.conv_layers = nn.ModuleList()
        in_ch = 1

        for i, out_ch in enumerate(channels):
            block = nn.Sequential(
                ConvBlock(
                    in_ch, out_ch,
                    kernel_size=8 if i == 0 else 4,
                    stride=2,
                    padding=3 if i == 0 else 1,
                    dropout=dropout * 0.5,
                ),
                DepthwiseSepConv(out_ch, out_ch, kernel_size=3),
                SEBlock(out_ch, reduction=8),
            )
            self.conv_layers.append(block)
            in_ch = out_ch

        # ── Global Pooling ──
        self.global_avg_pool = nn.AdaptiveAvgPool1d(1)
        self.global_max_pool = nn.AdaptiveMaxPool1d(1)

        # After pooling: channels[-1] * 2 (avg + max concatenated)
        pool_out_size = channels[-1] * 2

        # ── Classifier Head ──
        self.classifier = nn.Sequential(
            nn.Flatten(),
            nn.Linear(pool_out_size, 256),
            nn.BatchNorm1d(256),
            nn.GELU(),
            nn.Dropout(dropout),
            nn.Linear(256, 128),
            nn.BatchNorm1d(128),
            nn.GELU(),
            nn.Dropout(dropout * 0.5),
            nn.Linear(128, num_classes),
        )

        self._init_weights()

    def _init_weights(self):
        """Kaiming initialization."""
        for m in self.modules():
            if isinstance(m, nn.Conv1d):
                nn.init.kaiming_normal_(
                    m.weight, mode="fan_out", nonlinearity="relu"
                )
            elif isinstance(m, nn.Linear):
                nn.init.kaiming_normal_(
                    m.weight, mode="fan_out", nonlinearity="relu"
                )
                if m.bias is not None:
                    nn.init.zeros_(m.bias)
            elif isinstance(m, (nn.BatchNorm1d, nn.LayerNorm)):
                nn.init.ones_(m.weight)
                nn.init.zeros_(m.bias)

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        """
        Forward pass.

        Args:
            x: Input features (batch, input_size)

        Returns:
            Logits (batch, num_classes)
        """
        # Input projection
        x = self.input_proj(x)

        # Reshape to (batch, 1, input_size) for Conv1d
        x = x.unsqueeze(1)

        # Convolutional layers
        for conv_block in self.conv_layers:
            x = conv_block(x)

        # Dual pooling
        avg_pooled = self.global_avg_pool(x)
        max_pooled = self.global_max_pool(x)
        pooled = torch.cat([avg_pooled, max_pooled], dim=1)

        # Classification
        logits = self.classifier(pooled)

        return logits

    def get_feature_maps(
        self,
        x: torch.Tensor,
    ) -> List[torch.Tensor]:
        """
        Extract intermediate feature maps for visualization.

        Returns list of feature map tensors after each conv layer.
        """
        self.eval()
        feature_maps = []

        with torch.no_grad():
            x = self.input_proj(x)
            x = x.unsqueeze(1)

            for conv_block in self.conv_layers:
                x = conv_block(x)
                feature_maps.append(x.clone())

        return feature_maps

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
        """Predict single sample."""
        self.eval()
        with torch.no_grad():
            logits = self.forward(features.unsqueeze(0))
            probs = F.softmax(logits, dim=1)[0]
            pred = torch.argmax(probs).item()

        return {
            "verdict": "MALICIOUS" if pred == 1 else "BENIGN",
            "label": pred,
            "confidence": probs[pred].item(),
            "benign_prob": probs[0].item(),
            "malicious_prob": probs[1].item(),
        }

    def get_model_info(self) -> dict:
        """Return model info."""
        total = sum(p.numel() for p in self.parameters())
        trainable = sum(
            p.numel() for p in self.parameters() if p.requires_grad
        )
        return {
            "model_type": "CNNModel",
            "input_size": self.input_size,
            "num_classes": self.num_classes,
            "total_parameters": total,
            "trainable_parameters": trainable,
            "size_mb": round(total * 4 / 1024 / 1024, 2),
        }
