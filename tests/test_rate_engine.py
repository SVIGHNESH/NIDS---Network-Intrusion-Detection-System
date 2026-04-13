"""
tests/test_rate_engine.py
Unit tests for rate-based detection engine
"""

import time
import pytest
from nids.detectors.rate_engine import RateDetector
from nids.core.schemas import PacketEvent
from nids.core.config import RateDetectorConfig


class TestRateDetector:
    """Test cases for RateDetector"""

    @pytest.fixture
    def detector(self):
        """Create detector with low thresholds for testing"""
        config = RateDetectorConfig(
            port_scan_threshold=5,
            port_scan_window_sec=10,
            brute_force_threshold=3,
            brute_force_window_sec=30,
            syn_flood_threshold=10,
            syn_flood_window_sec=5,
            cooldown_sec=0,  # No cooldown for testing
        )
        return RateDetector(config)

    @pytest.fixture
    def packet_factory(self):
        """Create packet factory"""

        def create_packet(
            src_ip="1.1.1.1", dst_ip="10.0.0.1", dst_port=80, proto="TCP", flags="S"
        ):
            return PacketEvent(
                timestamp=time.time(),
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=50000,
                dst_port=dst_port,
                proto=proto,
                flags=flags,
                size=60,
            )

        return create_packet

    def test_port_scan_detection(self, detector, packet_factory):
        """Test port scan detection"""
        # Send packets to different ports
        for port in range(1, 10):
            pkt = packet_factory(dst_port=port)
            signals = detector.process(pkt)

        # Should trigger port scan alert
        assert len(signals) > 0
        assert signals[0].rule_id == "RATE-001"
        assert signals[0].severity == "high"

    def test_syn_flood_detection(self, detector, packet_factory):
        """Test SYN flood detection"""
        # Send many SYN packets
        for i in range(15):
            pkt = packet_factory(flags="S")
            signals = detector.process(pkt)

        # Should trigger SYN flood
        assert len(signals) > 0
        assert signals[0].rule_id == "RATE-003"
        assert signals[0].severity == "critical"

    def test_brute_force_detection(self, detector, packet_factory):
        """Test brute force detection"""
        # Send multiple auth attempts to same target
        for i in range(5):
            pkt = packet_factory(dst_port=22)  # SSH
            signals = detector.process(pkt)

        # Should trigger brute force
        assert len(signals) > 0
        assert signals[0].rule_id == "RATE-002"

    def test_no_alert_on_normal_traffic(self, detector, packet_factory):
        """Test that normal traffic doesn't trigger alerts"""
        # Send small number of packets to same port
        for i in range(3):
            pkt = packet_factory(dst_port=80)
            signals = detector.process(pkt)

        # No alerts
        assert len(signals) == 0

    def test_icmp_flood_detection(self, detector):
        """Test ICMP flood detection"""
        # Create ICMP packets
        for i in range(15):
            pkt = PacketEvent(
                timestamp=time.time(),
                src_ip="1.1.1.1",
                dst_ip="10.0.0.1",
                src_port=0,
                dst_port=0,
                proto="ICMP",
                flags="",
                size=64,
            )
            signals = detector.process(pkt)

        assert len(signals) > 0
        assert signals[0].rule_id == "RATE-004"

    def test_dns_flood_detection(self, detector):
        """Test DNS flood detection"""
        # Create DNS queries
        for i in range(60):
            pkt = PacketEvent(
                timestamp=time.time(),
                src_ip="1.1.1.1",
                dst_ip="8.8.8.8",
                src_port=50000,
                dst_port=53,
                proto="UDP",
                flags="",
                size=50,
            )
            signals = detector.process(pkt)

        assert len(signals) > 0
        assert signals[0].rule_id == "RATE-006"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
