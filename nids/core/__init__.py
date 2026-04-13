"""
nids/core/__init__.py
Core NIDS package exports
"""

from nids.core.config import Settings, get_settings
from nids.core.schemas import PacketEvent, SignalEvent, AlertEvent
from nids.core.correlation import AlertCorrelator
from nids.core.degradation import DegradationController, RuntimeProfile, Feature
from nids.core.metrics import MetricsCollector, SystemMetrics

__all__ = [
    "Settings",
    "get_settings",
    "PacketEvent",
    "SignalEvent",
    "AlertEvent",
    "AlertCorrelator",
    "DegradationController",
    "RuntimeProfile",
    "Feature",
    "MetricsCollector",
    "SystemMetrics",
]
