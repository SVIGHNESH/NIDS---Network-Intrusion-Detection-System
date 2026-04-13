"""
tests/test_correlation.py
Unit tests for alert correlation
"""

import time
import pytest
from nids.core.correlation import AlertCorrelator
from nids.core.schemas import SignalEvent
from nids.core.config import CorrelatorConfig


class TestAlertCorrelator:
    """Test cases for AlertCorrelator"""

    @pytest.fixture
    def correlator(self):
        """Create correlator with test config"""
        config = CorrelatorConfig(
            dedup_window_sec=0,  # No dedup for testing
            score_weights={
                "rate": 30,
                "yara": 50,
                "reputation": 40,
            },
            severity_thresholds={
                "critical": 100,
                "high": 70,
                "medium": 40,
                "low": 10,
            },
        )
        return AlertCorrelator(config)

    @pytest.fixture
    def signal_factory(self):
        """Create signal factory"""
        counter = [0]

        def create_signal(
            source="rate",
            rule_id="RATE-001",
            severity="high",
            src_ip="1.1.1.1",
            dst_ip="10.0.0.1",
            score_contrib=30,
        ):
            counter[0] += 1
            return SignalEvent(
                id=f"sig-{counter[0]}",
                timestamp=time.time(),
                source=source,
                rule_id=rule_id,
                severity=severity,
                src_ip=src_ip,
                dst_ip=dst_ip,
                dst_port=80,
                proto="TCP",
                description=f"Test signal {counter[0]}",
                score_contribution=score_contrib,
            )

        return create_signal

    def test_basic_signal_to_alert(self, correlator, signal_factory):
        """Test converting a single signal to alert"""
        signal = signal_factory()
        alerts = correlator.process_signals([signal])

        assert len(alerts) == 1
        alert = alerts[0]
        assert alert.src_ip == signal.src_ip
        assert alert.dst_ip == signal.dst_ip
        assert signal.rule_id in alert.rule_ids

    def test_score_calculation(self, correlator, signal_factory):
        """Test score calculation"""
        # High severity + score contrib
        signal = signal_factory(severity="high", score_contrib=30)
        alerts = correlator.process_signals([signal])

        assert alerts[0].score > 70

    def test_severity_mapping(self, correlator, signal_factory):
        """Test severity mapping from score"""
        # Critical severity
        signal = signal_factory(severity="critical")
        alerts = correlator.process_signals([signal])
        assert alerts[0].severity == "critical"

        # Low severity
        signal = signal_factory(severity="low", score_contrib=0)
        alerts = correlator.process_signals([signal])
        assert alerts[0].severity == "low"

    def test_multiple_signals(self, correlator, signal_factory):
        """Test multiple signals from same source"""
        signals = [
            signal_factory(rule_id="RATE-001"),
            signal_factory(rule_id="RATE-002"),
            signal_factory(rule_id="RATE-003"),
        ]
        alerts = correlator.process_signals(signals)

        # Should produce multiple alerts
        assert len(alerts) >= 3


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
