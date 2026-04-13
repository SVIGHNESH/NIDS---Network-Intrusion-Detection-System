"""
nids/detectors/yara_engine.py
Gated YARA signature detection engine
"""

import os
import time
import uuid
import logging
import threading
from typing import List, Optional, Set

from nids.core.schemas import PacketEvent, SignalEvent, Severity


logger = logging.getLogger("nids.detectors.yara")


class YaraDetector:
    """
    YARA-based signature detector with gating.
    Only scans suspicious traffic to preserve CPU on low-spec systems.
    """

    def __init__(
        self,
        rules_file: str = "nids_rules.yar",
        enabled: bool = True,
        timeout_ms: int = 1000,
        max_payload_size: int = 1024 * 1024,
        gating_enabled: bool = True,
        gating_ports: Optional[List[int]] = None,
    ):
        self.rules_file = rules_file
        self.enabled = enabled
        self.timeout_ms = timeout_ms
        self.max_payload_size = max_payload_size
        self.gating_enabled = gating_enabled
        self.gating_ports = set(gating_ports or [])
        self._rules = None
        self._lock = threading.Lock()
        self._initialized = False

    def initialize(self) -> bool:
        """Initialize YARA rules"""
        if not self.enabled:
            logger.info("YARA detector disabled")
            return True

        if not os.path.exists(self.rules_file):
            logger.warning(f"YARA rules file not found: {self.rules_file}")
            # Try alternate paths
            alt_paths = [
                os.path.join(os.path.dirname(__file__), "..", "..", self.rules_file),
                os.path.join(os.path.dirname(__file__), self.rules_file),
            ]
            for alt in alt_paths:
                if os.path.exists(alt):
                    self.rules_file = alt
                    break

        try:
            import yara
        except ImportError:
            logger.error("yara-python not installed. Install with: pip install yara")
            return False

        try:
            with self._lock:
                self._rules = yara.compile(self.rules_file)
            self._initialized = True
            logger.info(f"YARA rules loaded from {self.rules_file}")
            return True
        except Exception as e:
            logger.error(f"Failed to compile YARA rules: {e}")
            return False

    def process(self, packet: PacketEvent) -> List[SignalEvent]:
        """Process a packet and return any YARA signals"""
        if not self.enabled or not self._initialized:
            return []

        # Apply gating check
        if self.gating_enabled and not self._should_scan(packet):
            return []

        # Get payload to scan
        if not packet.payload_preview:
            return []

        # Limit payload size
        payload = bytes(packet.payload_preview[: self.max_payload_size])

        try:
            matches = self._rules.match(data=payload)
            if matches:
                return self._create_signals(packet, matches)
        except Exception as e:
            logger.error(f"YARA match error: {e}")

        return []

    def _should_scan(self, packet: PacketEvent) -> bool:
        """Determine if packet should be scanned based on gating rules"""
        # Scan suspicious ports
        if packet.dst_port in self.gating_ports:
            return True

        # Scan HTTP/HTTPS payloads
        if packet.dst_port in [80, 443, 8080, 8443]:
            return True

        # Scan SSH/FTP etc
        if packet.dst_port in [21, 22, 23, 25, 110, 143, 3389]:
            return True

        return False

    def _create_signals(self, packet: PacketEvent, matches: List) -> List[SignalEvent]:
        """Create signals from YARA matches"""
        signals = []
        severity_map = {
            "critical": Severity.CRITICAL,
            "high": Severity.HIGH,
            "medium": Severity.MEDIUM,
            "low": Severity.LOW,
        }

        for match in matches:
            # Extract rule metadata
            rule_id = match.rule
            severity = "medium"
            description = match.rule

            # Try to get severity from rule metadata
            if hasattr(match, "meta"):
                if "severity" in match.meta:
                    severity = match.meta["severity"]
                if "description" in match.meta:
                    description = match.meta["description"]
                if "id" in match.meta:
                    rule_id = match.meta["id"]

            signals.append(
                SignalEvent(
                    id=str(uuid.uuid4()),
                    timestamp=packet.timestamp,
                    source="yara",
                    rule_id=rule_id,
                    severity=severity_map.get(severity, Severity.MEDIUM).value,
                    src_ip=packet.src_ip,
                    dst_ip=packet.dst_ip,
                    dst_port=packet.dst_port,
                    proto=packet.proto,
                    description=description,
                    raw_match=str(match),
                    score_contribution=50,  # YARA has high weight
                    metadata={
                        "matched_strings": [str(s) for s in match.strings],
                        "tags": list(match.tags) if hasattr(match, "tags") else [],
                    },
                )
            )

        return signals

    def is_initialized(self) -> bool:
        """Check if YARA engine is initialized"""
        return self._initialized

    def reload_rules(self) -> bool:
        """Reload YARA rules from file"""
        return self.initialize()

    def get_stats(self) -> dict:
        """Get detector statistics"""
        return {
            "enabled": self.enabled,
            "initialized": self._initialized,
            "gating_enabled": self.gating_enabled,
            "gating_ports_count": len(self.gating_ports),
            "rules_file": self.rules_file,
        }


def create_yara_detector(config: dict) -> YaraDetector:
    """Factory function to create YaraDetector from config"""
    return YaraDetector(
        rules_file=config.get("rules_file", "nids_rules.yar"),
        enabled=config.get("enabled", True),
        timeout_ms=config.get("timeout_ms", 1000),
        max_payload_size=config.get("max_payload_size", 1024 * 1024),
        gating_enabled=config.get("gating_enabled", True),
        gating_ports=config.get(
            "gating_ports", [22, 23, 25, 80, 443, 445, 3306, 3389, 5432, 8080]
        ),
    )
