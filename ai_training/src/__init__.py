# ============================================
# SHADOW CATCHER - AI Training Source Package
# ============================================

__version__ = "1.0.0"
__author__ = "Shadow Catcher Team"
__description__ = "AI Training Pipeline for Shadow Brain Malware Classifier"

from pathlib import Path

# Package root directory
SRC_ROOT = Path(__file__).parent
AI_ROOT = SRC_ROOT.parent

# Default paths
DEFAULT_DATASET_DIR = AI_ROOT / "datasets"
DEFAULT_OUTPUT_DIR = AI_ROOT / "outputs"
DEFAULT_CHECKPOINT_DIR = DEFAULT_OUTPUT_DIR / "checkpoints"
DEFAULT_LOG_DIR = DEFAULT_OUTPUT_DIR / "logs"
DEFAULT_EXPORT_DIR = DEFAULT_OUTPUT_DIR / "exported"

# Model constants
INPUT_SIZE = 512          # Number of bytes to analyze per file
NUM_CLASSES = 2           # 0=benign, 1=malicious
CLASS_NAMES = ["benign", "malicious"]

# Feature constants
MAGIC_BYTES_SIZE = 16     # First 16 bytes for magic detection
HEADER_SIZE = 512         # Full header size for analysis
ENTROPY_WINDOW = 256      # Window size for entropy calculation

__all__ = [
    "__version__",
    "__author__",
    "SRC_ROOT",
    "AI_ROOT",
    "DEFAULT_DATASET_DIR",
    "DEFAULT_OUTPUT_DIR",
    "DEFAULT_CHECKPOINT_DIR",
    "DEFAULT_LOG_DIR",
    "DEFAULT_EXPORT_DIR",
    "INPUT_SIZE",
    "NUM_CLASSES",
    "CLASS_NAMES",
    "MAGIC_BYTES_SIZE",
    "HEADER_SIZE",
    "ENTROPY_WINDOW",
]
