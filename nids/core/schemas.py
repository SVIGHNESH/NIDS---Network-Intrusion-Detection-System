"""
nids/core/schemas.py
Canonical event schemas for NIDS data flow
"""

import time
from dataclasses import dataclass, field, asdict
from typing import Optional, Literal
from enum import Enum


class Severity(str, Enum):
    """Alert severity levels"""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class Protocol(str, Enum):
    """Network protocols"""

    TCP = "TCP"
    UDP = "UDP"
    ICMP = "ICMP"
    OTHER = "OTHER"


class SignalSource(str, Enum):
    """Signal source identifiers"""

    RATE = "rate"
    YARA = "yara"
    REPUTATION = "reputation"
    ML = "ml"


@dataclass
class PacketEvent:
    """
    Normalized packet metadata event.
    This is the canonical input to the detection pipeline.
    """

    timestamp: float = field(default_factory=time.time)
    src_ip: str = ""
    dst_ip: str = ""
    src_port: int = 0
    dst_port: int = 0
    proto: str = "OTHER"
    flags: str = ""
    size: int = 0
    payload_preview: bytes = b""

    def to_dict(self) -> dict:
        d = asdict(self)
        d["timestamp_human"] = time.strftime(
            "%Y-%m-%d %H:%M:%S", time.localtime(self.timestamp)
        )
        return d

    def __str__(self) -> str:
        return (
            f"PacketEvent({self.proto} {self.src_ip}:{self.src_port} -> "
            f"{self.dst_ip}:{self.dst_port} size={self.size} flags={self.flags})"
        )


@dataclass
class SignalEvent:
    """
    Detection signal from a single detector engine.
    Emitted when a rule threshold is exceeded.
    """

    id: str = ""
    timestamp: float = field(default_factory=time.time)
    source: str = ""  # rate, yara, reputation, ml
    rule_id: str = ""
    severity: str = "low"
    src_ip: str = ""
    dst_ip: str = ""
    dst_port: Optional[int] = None
    proto: str = "OTHER"
    description: str = ""
    raw_match: Optional[str] = None
    score_contribution: int = 0
    metadata: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        d = asdict(self)
        d["timestamp_human"] = time.strftime(
            "%Y-%m-%d %H:%M:%S", time.localtime(self.timestamp)
        )
        return d

    def __str__(self) -> str:
        return (
            f"Signal({self.source}/{self.rule_id} {self.severity} "
            f"{self.src_ip} -> {self.dst_ip}:{self.dst_port})"
        )


@dataclass
class AlertEvent:
    """
    Correlated alert event combining multiple signals.
    The primary output of the NIDS pipeline.
    """

    id: str = ""
    timestamp: float = field(default_factory=time.time)
    severity: str = "low"
    title: str = ""
    description: str = ""
    src_ip: str = ""
    dst_ip: str = ""
    dst_port: Optional[int] = None
    proto: str = "OTHER"
    rule_ids: list[str] = field(default_factory=list)
    signal_count: int = 0
    score: int = 0
    raw_signals: list[dict] = field(default_factory=list)
    metadata: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        d = asdict(self)
        d["timestamp_human"] = time.strftime(
            "%Y-%m-%d %H:%M:%S", time.localtime(self.timestamp)
        )
        return d

    def __str__(self) -> str:
        return (
            f"Alert({self.severity.upper()}] {self.title} "
            f"{self.src_ip} -> {self.dst_ip}:{self.dst_port} score={self.score})"
        )


# Schema version for compatibility tracking
SCHEMA_VERSION = "1.0.0"
