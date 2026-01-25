"""
Deception Technology Detection Module

Identifies defensive deception infrastructure including:
- Honeypots (web, SSH, service-level)
- DNS Sinkholes
- Network Tarpits

Each detection includes a confidence score (0-100) and risk rating.
"""

from .scoring import DeceptionScorer
from .honeypots import HoneypotDetector
from .sinkholes import SinkholeDetector
from .tarpits import TarpitDetector

__all__ = [
    "DeceptionScorer",
    "HoneypotDetector",
    "SinkholeDetector",
    "TarpitDetector",
]
