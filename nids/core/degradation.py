"""
nids/core/degradation.py
Low-spec performance and degradation controller
"""

import time
import logging
import threading
from typing import Dict, Optional
from dataclasses import dataclass, field
from enum import Enum

logger = logging.getLogger("nids.degradation")


class Feature(Enum):
    """Features that can be enabled/disabled"""

    RATE_DETECTION = "rate_detection"
    YARA_DETECTION = "yara_detection"
    REPUTATION_ENRICHMENT = "reputation_enrichment"
    ML_ANOMALY = "ml_anomaly"


class RuntimeProfile(Enum):
    """Runtime profiles for different hardware"""

    LITE = "lite"  # Default for low-spec (i5/8GB)
    ENHANCED = "enhanced"  # Full features when resources allow


@dataclass
class DegradationState:
    """Current state of each feature"""

    rate_detection: bool = True
    yara_detection: bool = True
    reputation_enrichment: bool = True
    ml_anomaly: bool = False


@dataclass
class SystemMetrics:
    """System resource metrics"""

    cpu_percent: float = 0.0
    memory_percent: float = 0.0
    queue_depth: int = 0
    packets_dropped: int = 0
    packets_processed: int = 0
    avg_processing_latency_ms: float = 0.0
    timestamp: float = field(default_factory=time.time)


class DegradationController:
    """
    Controls feature degradation based on system resources.
    Ensures core detection remains active under high load.
    """

    # Degradation order (first to disable -> last to disable)
    DEGRADATION_ORDER = [
        Feature.ML_ANOMALY,
        Feature.REPUTATION_ENRICHMENT,
        Feature.YARA_DETECTION,
    ]

    def __init__(
        self,
        profile: RuntimeProfile = RuntimeProfile.LITE,
        cpu_threshold_percent: float = 80.0,
        memory_threshold_percent: float = 85.0,
        queue_threshold: int = 800,
        drop_threshold: int = 100,
    ):
        self.profile = profile
        self.cpu_threshold = cpu_threshold_percent
        self.memory_threshold = memory_threshold_percent
        self.queue_threshold = queue_threshold
        self.drop_threshold = drop_threshold

        self._state = DegradationState()
        self._state_lock = threading.Lock()

        # Track metrics history for trend analysis
        self._metrics_history: list[SystemMetrics] = []
        self._max_history = 30

        # Manual override
        self._manual_overrides: Dict[Feature, bool] = {}

        logger.info(f"DegradationController initialized with profile: {profile.value}")

    def get_state(self) -> DegradationState:
        """Get current degradation state"""
        with self._state_lock:
            return DegradationState(
                rate_detection=self._state.rate_detection,
                yara_detection=self._state.yara_detection,
                reputation_enrichment=self._state.reputation_enrichment,
                ml_anomaly=self._state.ml_anomaly,
            )

    def is_enabled(self, feature: Feature) -> bool:
        """Check if a feature is currently enabled"""
        # Check manual override first
        if feature in self._manual_overrides:
            return self._manual_overrides[feature]

        state = self.get_state()

        feature_map = {
            Feature.RATE_DETECTION: state.rate_detection,
            Feature.YARA_DETECTION: state.yara_detection,
            Feature.REPUTATION_ENRICHMENT: state.reputation_enrichment,
            Feature.ML_ANOMALY: state.ml_anomaly,
        }
        return feature_map.get(feature, False)

    def set_override(self, feature: Feature, enabled: bool):
        """Manually override a feature's enabled state"""
        self._manual_overrides[feature] = enabled
        logger.info(f"Manual override set: {feature.value} = {enabled}")

    def clear_override(self, feature: Feature):
        """Clear manual override for a feature"""
        if feature in self._manual_overrides:
            del self._manual_overrides[feature]
            logger.info(f"Manual override cleared: {feature.value}")

    def update_metrics(self, metrics: SystemMetrics):
        """Update system metrics and evaluate degradation"""
        self._metrics_history.append(metrics)
        if len(self._metrics_history) > self._max_history:
            self._metrics_history.pop(0)

        # Only evaluate if profile is LITE
        if self.profile != RuntimeProfile.LITE:
            return

        # Check if degradation is needed
        self._evaluate_degradation(metrics)

    def _evaluate_degradation(self, metrics: SystemMetrics):
        """Evaluate and apply degradation based on metrics"""
        should_degrade = False
        reasons = []

        # Check CPU
        if metrics.cpu_percent > self.cpu_threshold:
            should_degrade = True
            reasons.append(f"CPU {metrics.cpu_percent:.1f}% > {self.cpu_threshold}%")

        # Check memory
        if metrics.memory_percent > self.memory_threshold:
            should_degrade = True
            reasons.append(
                f"Memory {metrics.memory_percent:.1f}% > {self.memory_threshold}%"
            )

        # Check queue depth
        if metrics.queue_depth > self.queue_threshold:
            should_degrade = True
            reasons.append(f"Queue {metrics.queue_depth} > {self.queue_threshold}")

        # Check packet drops
        if metrics.packets_dropped > self.drop_threshold:
            should_degrade = True
            reasons.append(f"Drops {metrics.packets_dropped} > {self.drop_threshold}")

        if should_degrade:
            logger.warning(f"Degradation triggered: {', '.join(reasons)}")
            self._apply_degradation()
        else:
            # Try to recover disabled features
            self._try_recovery(metrics)

    def _apply_degradation(self):
        """Apply degradation by disabling features in order"""
        with self._state_lock:
            for feature in self.DEGRADATION_ORDER:
                if self._should_disable(feature):
                    self._disable_feature(feature)

    def _should_disable(self, feature: Feature) -> bool:
        """Check if a feature should be disabled"""
        if feature in self._manual_overrides:
            return False  # Don't override manual setting

        state_map = {
            Feature.YARA_DETECTION: self._state.yara_detection,
            Feature.REPUTATION_ENRICHMENT: self._state.reputation_enrichment,
            Feature.ML_ANOMALY: self._state.ml_anomaly,
        }
        return state_map.get(feature, False)

    def _disable_feature(self, feature: Feature):
        """Disable a specific feature"""
        with self._state_lock:
            if feature == Feature.YARA_DETECTION:
                self._state.yara_detection = False
                logger.warning("YARA detection DISABLED due to high load")
            elif feature == Feature.REPUTATION_ENRICHMENT:
                self._state.reputation_enrichment = False
                logger.warning("Reputation enrichment DISABLED due to high load")
            elif feature == Feature.ML_ANOMALY:
                self._state.ml_anomaly = False
                logger.warning("ML anomaly detection DISABLED due to high load")

    def _try_recovery(self, metrics: SystemMetrics):
        """Try to recover disabled features if resources allow"""
        with self._state_lock:
            # Calculate if we have headroom
            cpu_headroom = self.cpu_threshold - metrics.cpu_percent
            memory_headroom = self.memory_threshold - metrics.memory_percent

            # Need significant headroom to re-enable
            headroom_required = 20.0

            if cpu_headroom > headroom_required and memory_headroom > headroom_required:
                # Try to re-enable features in reverse order
                recovery_order = reversed(self.DEGRADATION_ORDER)
                for feature in recovery_order:
                    if self._should_enable(feature):
                        self._enable_feature(feature)

    def _should_enable(self, feature: Feature) -> bool:
        """Check if a feature should be enabled"""
        if feature in self._manual_overrides:
            return False

        state_map = {
            Feature.YARA_DETECTION: not self._state.yara_detection,
            Feature.REPUTATION_ENRICHMENT: not self._state.reputation_enrichment,
            Feature.ML_ANOMALY: not self._state.ml_anomaly,
        }
        return state_map.get(feature, False)

    def _enable_feature(self, feature: Feature):
        """Enable a specific feature"""
        with self._state_lock:
            if feature == Feature.YARA_DETECTION:
                self._state.yara_detection = True
                logger.info("YARA detection re-enabled")
            elif feature == Feature.REPUTATION_ENRICHMENT:
                self._state.reputation_enrichment = True
                logger.info("Reputation enrichment re-enabled")
            elif feature == Feature.ML_ANOMALY:
                self._state.ml_anomaly = True
                logger.info("ML anomaly detection re-enabled")

    def get_stats(self) -> dict:
        """Get degradation controller statistics"""
        state = self.get_state()

        # Calculate trend from history
        avg_cpu = 0.0
        avg_memory = 0.0
        if self._metrics_history:
            avg_cpu = sum(m.cpu_percent for m in self._metrics_history) / len(
                self._metrics_history
            )
            avg_memory = sum(m.memory_percent for m in self._metrics_history) / len(
                self._metrics_history
            )

        return {
            "profile": self.profile.value,
            "state": {
                "rate_detection": state.rate_detection,
                "yara_detection": state.yara_detection,
                "reputation_enrichment": state.reputation_enrichment,
                "ml_anomaly": state.ml_anomaly,
            },
            "thresholds": {
                "cpu": self.cpu_threshold,
                "memory": self.memory_threshold,
                "queue": self.queue_threshold,
                "drops": self.drop_threshold,
            },
            "current_metrics": {
                "avg_cpu": avg_cpu,
                "avg_memory": avg_memory,
                "samples": len(self._metrics_history),
            },
            "manual_overrides": {f.value: v for f, v in self._manual_overrides.items()},
        }


def create_degradation_controller(
    profile: str = "lite", config: dict = None
) -> DegradationController:
    """Factory function to create degradation controller"""
    profile_enum = RuntimeProfile.LITE if profile == "lite" else RuntimeProfile.ENHANCED

    kwargs = {}
    if config:
        kwargs = {
            "cpu_threshold_percent": config.get("cpu_threshold", 80.0),
            "memory_threshold_percent": config.get("memory_threshold", 85.0),
            "queue_threshold": config.get("queue_threshold", 800),
            "drop_threshold": config.get("drop_threshold", 100),
        }

    return DegradationController(profile=profile_enum, **kwargs)
