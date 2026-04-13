"""
nids/core/correlation.py
Alert correlator and scoring pipeline
"""

import time
import uuid
import logging
from typing import List, Dict, Optional
from collections import defaultdict
from dataclasses import dataclass, field

from nids.core.schemas import PacketEvent, SignalEvent, AlertEvent, Severity
from nids.core.config import CorrelatorConfig


logger = logging.getLogger("nids.correlation")


@dataclass
class SignalGroup:
    """Group of related signals for correlation"""

    signals: List[SignalEvent] = field(default_factory=list)
    src_ip: str = ""
    dst_ip: str = ""
    first_timestamp: float = 0
    last_timestamp: float = 0


class AlertCorrelator:
    """
    Alert correlator that merges signals into actionable alerts.
    Handles deduplication, scoring, and severity mapping.
    """

    def __init__(self, config: Optional[CorrelatorConfig] = None):
        self.config = config or CorrelatorConfig()
        self._dedup_cache: Dict[str, float] = {}
        self._signal_buffer: Dict[str, SignalGroup] = {}
        self._buffer_timeout_sec = 60  # Max time to hold signals for correlation
        logger.info("AlertCorrelator initialized")

    def process_signals(self, signals: List[SignalEvent]) -> List[AlertEvent]:
        """
        Process a batch of signals and produce correlated alerts.
        """
        alerts: List[AlertEvent] = []

        for signal in signals:
            # Check deduplication
            if self._is_suppressed(signal):
                logger.debug(
                    f"Signal suppressed by dedup: {signal.rule_id} from {signal.src_ip}"
                )
                continue

            # Create alert from signal
            alert = self._signal_to_alert(signal)
            alerts.append(alert)

            # Mark as deduplicated
            self._dedup_cache[self._get_dedup_key(signal)] = signal.timestamp

        return alerts

    def _is_suppressed(self, signal: SignalEvent) -> bool:
        """Check if signal should be suppressed due to recent duplicate"""
        key = self._get_dedup_key(signal)
        last_seen = self._dedup_cache.get(key, 0)
        return (signal.timestamp - last_seen) < self.config.dedup_window_sec

    def _get_dedup_key(self, signal: SignalEvent) -> str:
        """Generate deduplication key for a signal"""
        return f"{signal.rule_id}:{signal.src_ip}:{signal.dst_ip}:{signal.dst_port}"

    def _signal_to_alert(self, signal: SignalEvent) -> AlertEvent:
        """Convert a signal to an alert with scoring"""
        # Calculate total score
        score = self._calculate_score(signal)

        # Determine severity from score
        severity = self._score_to_severity(score)

        # Generate title
        title = self._generate_title(signal)

        return AlertEvent(
            id=str(uuid.uuid4()),
            timestamp=signal.timestamp,
            severity=severity,
            title=title,
            description=signal.description,
            src_ip=signal.src_ip,
            dst_ip=signal.dst_ip,
            dst_port=signal.dst_port,
            proto=signal.proto,
            rule_ids=[signal.rule_id],
            signal_count=1,
            score=score,
            raw_signals=[signal.to_dict()],
            metadata=signal.metadata,
        )

    def _calculate_score(self, signal: SignalEvent) -> int:
        """Calculate composite score from signal"""
        # Base score from severity (preserve original severity)
        base_scores = {
            "critical": 100,
            "high": 70,
            "medium": 40,
            "low": 10,
        }
        base = base_scores.get(signal.severity, 10)

        # Add minimal signal contribution (just for enrichment)
        score = base + min(signal.score_contribution, 10)

        # Cap at 100
        return min(score, 100)

    def _score_to_severity(self, score: int) -> str:
        """Map score to severity level"""
        thresholds = self.config.severity_thresholds

        if score >= thresholds.get("critical", 100):
            return Severity.CRITICAL.value
        elif score >= thresholds.get("high", 70):
            return Severity.HIGH.value
        elif score >= thresholds.get("medium", 40):
            return Severity.MEDIUM.value
        else:
            return Severity.LOW.value

    def _generate_title(self, signal: SignalEvent) -> str:
        """Generate human-readable alert title"""
        rule_titles = {
            "RATE-001": "Port Scan Detected",
            "RATE-002": "Brute Force Attack",
            "RATE-003": "SYN Flood Detected",
            "RATE-004": "ICMP Flood Detected",
            "RATE-005": "Host Sweep Detected",
            "RATE-006": "DNS Flood Detected",
            "RATE-007": "Data Exfiltration Detected",
        }

        if signal.source == "rate" and signal.rule_id in rule_titles:
            return rule_titles[signal.rule_id]
        elif signal.source == "yara":
            return f"Signature Match: {signal.rule_id}"
        elif signal.source == "reputation":
            return "Malicious IP Detected"
        else:
            return f"Alert: {signal.rule_id}"

    def merge_signals(self, signals: List[SignalEvent]) -> List[AlertEvent]:
        """
        Merge multiple related signals into a single alert.
        Uses source IP + destination as correlation key.
        """
        # Group signals by entity
        groups: Dict[str, SignalGroup] = defaultdict(SignalGroup)

        for signal in signals:
            key = f"{signal.src_ip}:{signal.dst_ip}"
            if key not in groups:
                groups[key] = SignalGroup(
                    src_ip=signal.src_ip,
                    dst_ip=signal.dst_ip,
                    first_timestamp=signal.timestamp,
                    last_timestamp=signal.timestamp,
                )
            groups[key].signals.append(signal)
            groups[key].last_timestamp = max(
                groups[key].last_timestamp, signal.timestamp
            )

        # Convert groups to alerts
        alerts = []
        for key, group in groups.items():
            if self._is_suppressed_by_group(group):
                continue

            alert = self._group_to_alert(group)
            alerts.append(alert)

            # Mark all signals in group as deduplicated
            for signal in group.signals:
                self._dedup_cache[self._get_dedup_key(signal)] = signal.timestamp

        return alerts

    def _is_suppressed_by_group(self, group: SignalGroup) -> bool:
        """Check if entire group should be suppressed"""
        if not group.signals:
            return True
        first_signal = group.signals[0]
        return self._is_suppressed(first_signal)

    def _group_to_alert(self, group: SignalGroup) -> AlertEvent:
        """Convert signal group to alert"""
        # Aggregate data
        signals = group.signals
        total_score = sum(self._calculate_score(s) for s in signals)
        avg_score = total_score // len(signals)

        # Use highest severity
        severity_order = ["critical", "high", "medium", "low"]
        severities = [s.severity for s in signals]
        highest_severity = min(severities, key=lambda x: severity_order.index(x))

        # Combine descriptions
        descriptions = list(set(s.description for s in signals))
        description = "; ".join(descriptions[:3])
        if len(descriptions) > 3:
            description += f" (+{len(descriptions) - 3} more)"

        # Rule IDs
        rule_ids = list(set(s.rule_id for s in signals))

        # Title
        title = f"Multiple Events from {group.src_ip}"
        if len(rule_ids) == 1:
            rule_titles = {
                "RATE-001": "Port Scan Detected",
                "RATE-002": "Brute Force Attack",
                "RATE-003": "SYN Flood Detected",
                "RATE-004": "ICMP Flood Detected",
                "RATE-005": "Host Sweep Detected",
                "RATE-006": "DNS Flood Detected",
                "RATE-007": "Data Exfiltration Detected",
            }
            title = rule_titles.get(rule_ids[0], f"Alert: {rule_ids[0]}")

        return AlertEvent(
            id=str(uuid.uuid4()),
            timestamp=group.first_timestamp,
            severity=highest_severity,
            title=title,
            description=description,
            src_ip=group.src_ip,
            dst_ip=group.dst_ip,
            dst_port=signals[0].dst_port,
            proto=signals[0].proto,
            rule_ids=rule_ids,
            signal_count=len(signals),
            score=avg_score,
            raw_signals=[s.to_dict() for s in signals],
            metadata={"last_timestamp": group.last_timestamp},
        )

    def cleanup_old_cache(self, max_age_sec: int = 3600):
        """Clean up old deduplication cache entries"""
        now = time.time()
        keys_to_remove = [
            k for k, v in self._dedup_cache.items() if (now - v) > max_age_sec
        ]
        for k in keys_to_remove:
            del self._dedup_cache[k]

    def get_stats(self) -> dict:
        """Get correlator statistics"""
        return {
            "dedup_cache_size": len(self._dedup_cache),
            "signal_buffer_size": len(self._signal_buffer),
        }
