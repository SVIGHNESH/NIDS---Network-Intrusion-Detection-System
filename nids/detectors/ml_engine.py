"""
nids/detectors/ml_engine.py
Unsupervised ML anomaly detector (IsolationForest) for packet-level features.
"""

import os
import time
import uuid
import ipaddress
import logging
import threading
from typing import List, Optional, Tuple

from nids.core.schemas import PacketEvent, SignalEvent, Severity
from nids.core.config import MLDetectorConfig


logger = logging.getLogger("nids.detectors.ml")


FEATURE_NAMES = [
    "size",
    "proto_code",
    "dst_port",
    "src_port_ephemeral",
    "tcp_flags_bitmap",
    "is_syn",
    "is_ack",
    "is_private_src",
    "hour_of_day",
    "payload_len",
]

_PROTO_CODES = {"TCP": 1, "UDP": 2, "ICMP": 3}

_FLAG_BITS = {"F": 1, "S": 2, "R": 4, "P": 8, "A": 16, "U": 32, "E": 64, "C": 128}


def _is_private_ip(ip: str) -> bool:
    """Return True if the address is in RFC1918 / loopback / link-local space."""
    if not ip:
        return False
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return addr.is_private or addr.is_loopback or addr.is_link_local


def _flags_bitmap(flags: str) -> int:
    """Convert a TCP-flag string (e.g., 'SA') to an integer bitmap."""
    bitmap = 0
    for ch in (flags or "").upper():
        bitmap |= _FLAG_BITS.get(ch, 0)
    return bitmap


def extract_features(packet: PacketEvent) -> List[float]:
    """Extract a fixed-length numeric feature vector from a PacketEvent."""
    flags_bitmap = _flags_bitmap(packet.flags)
    is_syn = 1 if (flags_bitmap & _FLAG_BITS["S"]) and not (flags_bitmap & _FLAG_BITS["A"]) else 0
    is_ack = 1 if flags_bitmap & _FLAG_BITS["A"] else 0
    hour = time.localtime(packet.timestamp).tm_hour
    payload_len = len(packet.payload_preview) if packet.payload_preview else 0

    return [
        float(packet.size),
        float(_PROTO_CODES.get((packet.proto or "").upper(), 0)),
        float(packet.dst_port),
        1.0 if packet.src_port >= 49152 else 0.0,
        float(flags_bitmap),
        float(is_syn),
        float(is_ack),
        1.0 if _is_private_ip(packet.src_ip) else 0.0,
        float(hour),
        float(payload_len),
    ]


class MLDetector:
    """
    IsolationForest-based anomaly detector.
    Degrades gracefully if the serialized model is missing.
    """

    def __init__(self, config: MLDetectorConfig):
        self.config = config
        self.enabled = config.enabled
        self._model = None
        self._initialized = False
        self._lock = threading.Lock()
        self._last_alert: dict = {}
        self._inferences = 0
        self._signals_emitted = 0

    def initialize(self) -> bool:
        if not self.enabled:
            logger.info("ML detector disabled by config")
            return True

        if not os.path.exists(self.config.model_path):
            logger.warning(
                f"ML model file not found: {self.config.model_path} — "
                "ML detector will remain disabled. Train with: "
                "python -m nids.detectors.ml_train --help"
            )
            return False

        try:
            import joblib  # lazy import keeps lite profile lean
        except ImportError:
            logger.error("joblib not installed — cannot load ML model")
            return False

        try:
            with self._lock:
                self._model = joblib.load(self.config.model_path)
            self._initialized = True
            logger.info(f"ML model loaded from {self.config.model_path}")
            return True
        except Exception as e:
            logger.error(f"Failed to load ML model: {e}")
            return False

    def process(self, packet: PacketEvent) -> List[SignalEvent]:
        if not self.enabled or not self._initialized or self._model is None:
            return []

        try:
            features = extract_features(packet)
            score = float(self._model.score_samples([features])[0])
            self._inferences += 1
        except Exception as e:
            logger.error(f"ML inference error: {e}")
            return []

        severity, score_contribution = self._grade(score)
        if severity is None:
            return []

        if self._in_cooldown(packet.src_ip, packet.timestamp):
            return []

        self._last_alert[packet.src_ip] = packet.timestamp
        self._signals_emitted += 1

        return [
            SignalEvent(
                id=str(uuid.uuid4()),
                timestamp=packet.timestamp,
                source="ml",
                rule_id="ML-IFOREST-ANOMALY",
                severity=severity,
                src_ip=packet.src_ip,
                dst_ip=packet.dst_ip,
                dst_port=packet.dst_port,
                proto=packet.proto,
                description=f"IsolationForest anomaly (score={score:.3f})",
                raw_match=None,
                score_contribution=score_contribution,
                metadata={
                    "anomaly_score": score,
                    "model_version": "iforest-v1",
                    "features": dict(zip(FEATURE_NAMES, features)),
                },
            )
        ]

    def _grade(self, score: float) -> Tuple[Optional[str], int]:
        if score <= self.config.high_threshold:
            return Severity.HIGH.value, 8
        if score <= self.config.medium_threshold:
            return Severity.MEDIUM.value, 5
        return None, 0

    def _in_cooldown(self, src_ip: str, now: float) -> bool:
        last = self._last_alert.get(src_ip)
        if last is None:
            return False
        return (now - last) < self.config.cooldown_sec

    def is_initialized(self) -> bool:
        return self._initialized

    def get_stats(self) -> dict:
        return {
            "enabled": self.enabled,
            "initialized": self._initialized,
            "model_path": self.config.model_path,
            "inferences": self._inferences,
            "signals_emitted": self._signals_emitted,
            "cooldown_tracked_ips": len(self._last_alert),
        }
