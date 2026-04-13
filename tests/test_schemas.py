"""
tests/test_schemas.py
Unit tests for canonical schemas
"""

import time
import pytest
from nids.core.schemas import PacketEvent, SignalEvent, AlertEvent, Severity


class TestPacketEvent:
    """Test cases for PacketEvent"""

    def test_creation(self):
        """Test creating a PacketEvent"""
        pkt = PacketEvent(
            timestamp=time.time(),
            src_ip="192.168.1.100",
            dst_ip="10.0.0.1",
            src_port=54321,
            dst_port=22,
            proto="TCP",
            flags="S",
            size=60,
        )

        assert pkt.src_ip == "192.168.1.100"
        assert pkt.dst_ip == "10.0.0.1"
        assert pkt.dst_port == 22
        assert pkt.proto == "TCP"

    def test_to_dict(self):
        """Test serialization to dict"""
        pkt = PacketEvent(
            timestamp=1000.0,  # Fixed timestamp for testing
            src_ip="192.168.1.100",
            dst_ip="10.0.0.1",
            src_port=54321,
            dst_port=22,
            proto="TCP",
            flags="S",
            size=60,
        )

        d = pkt.to_dict()
        assert "timestamp_human" in d
        assert d["src_ip"] == "192.168.1.100"

    def test_str_representation(self):
        """Test string representation"""
        pkt = PacketEvent(
            src_ip="192.168.1.100",
            dst_ip="10.0.0.1",
            src_port=54321,
            dst_port=22,
            proto="TCP",
            size=60,
        )

        s = str(pkt)
        assert "TCP" in s
        assert "192.168.1.100" in s


class TestSignalEvent:
    """Test cases for SignalEvent"""

    def test_creation(self):
        """Test creating a SignalEvent"""
        signal = SignalEvent(
            id="test-123",
            timestamp=time.time(),
            source="rate",
            rule_id="RATE-001",
            severity="high",
            src_ip="1.1.1.1",
            dst_ip="10.0.0.1",
            dst_port=80,
            description="Port scan detected",
            score_contribution=70,
        )

        assert signal.id == "test-123"
        assert signal.source == "rate"
        assert signal.rule_id == "RATE-001"

    def test_to_dict(self):
        """Test serialization to dict"""
        signal = SignalEvent(
            timestamp=1000.0,
            source="yara",
            rule_id="WEB-001",
            severity="critical",
            src_ip="2.2.2.2",
            description="SQL injection",
            score_contribution=50,
        )

        d = signal.to_dict()
        assert "timestamp_human" in d
        assert d["source"] == "yara"


class TestAlertEvent:
    """Test cases for AlertEvent"""

    def test_creation(self):
        """Test creating an AlertEvent"""
        alert = AlertEvent(
            id="alert-123",
            timestamp=time.time(),
            severity="high",
            title="Port Scan Detected",
            description="Multiple ports scanned",
            src_ip="1.1.1.1",
            dst_ip="10.0.0.1",
            rule_ids=["RATE-001"],
            signal_count=1,
            score=85,
        )

        assert alert.id == "alert-123"
        assert alert.severity == "high"
        assert alert.score == 85

    def test_to_dict(self):
        """Test serialization to dict"""
        alert = AlertEvent(
            timestamp=1000.0,
            severity="critical",
            title="SYN Flood",
            src_ip="3.3.3.3",
            rule_ids=["RATE-003"],
            score=100,
        )

        d = alert.to_dict()
        assert "timestamp_human" in d
        assert d["severity"] == "critical"


class TestEnums:
    """Test enum values"""

    def test_severity_values(self):
        """Test Severity enum values"""
        assert Severity.CRITICAL.value == "critical"
        assert Severity.HIGH.value == "high"
        assert Severity.MEDIUM.value == "medium"
        assert Severity.LOW.value == "low"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
