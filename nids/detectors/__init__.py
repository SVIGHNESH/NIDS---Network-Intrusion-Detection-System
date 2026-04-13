"""
nids/detectors/__init__.py
Detector package exports
"""

from nids.detectors.rate_engine import RateDetector
from nids.detectors.yara_engine import YaraDetector

__all__ = ["RateDetector", "YaraDetector"]
