"""
tests/test_ml_engine.py
Unit tests for the IsolationForest ML detector.
"""

import time
import pytest

from nids.core.schemas import PacketEvent
from nids.core.config import MLDetectorConfig
from nids.detectors.ml_engine import MLDetector, extract_features, FEATURE_NAMES


pytest.importorskip("sklearn", reason="scikit-learn not installed")
pytest.importorskip("joblib", reason="joblib not installed")


def _packet(**overrides) -> PacketEvent:
    defaults = dict(
        timestamp=time.time(),
        src_ip="10.0.0.5",
        dst_ip="8.8.8.8",
        src_port=50000,
        dst_port=443,
        proto="TCP",
        flags="SA",
        size=120,
        payload_preview=b"",
    )
    defaults.update(overrides)
    return PacketEvent(**defaults)


def _train_tmp_model(tmp_path):
    """Fit a tiny IsolationForest on synthetic 'normal' traffic and save it."""
    import numpy as np
    from sklearn.ensemble import IsolationForest
    import joblib

    rng = np.random.default_rng(0)
    normal = []
    for _ in range(300):
        normal.append(
            extract_features(
                _packet(
                    size=int(rng.integers(60, 200)),
                    src_port=int(rng.integers(49152, 65535)),
                    dst_port=443,
                )
            )
        )
    X = np.array(normal, dtype=float)
    model = IsolationForest(n_estimators=50, contamination=0.01, random_state=42)
    model.fit(X)

    out = tmp_path / "iforest.pkl"
    joblib.dump(model, str(out))
    return str(out)


def test_extract_features_vector_shape():
    packet = _packet(size=500, payload_preview=b"hello")
    features = extract_features(packet)
    assert len(features) == len(FEATURE_NAMES)
    assert all(isinstance(f, float) for f in features)


def test_missing_model_disables_detector(tmp_path):
    cfg = MLDetectorConfig(enabled=True, model_path=str(tmp_path / "nope.pkl"))
    detector = MLDetector(cfg)
    assert detector.initialize() is False
    assert detector.is_initialized() is False
    assert detector.process(_packet()) == []


def test_anomaly_produces_signal(tmp_path):
    model_path = _train_tmp_model(tmp_path)
    cfg = MLDetectorConfig(enabled=True, model_path=model_path, medium_threshold=0.5, high_threshold=0.0)
    detector = MLDetector(cfg)
    assert detector.initialize() is True

    # Wildly out-of-distribution packet (huge size, unusual port, ICMP)
    outlier = _packet(size=65000, dst_port=1, proto="ICMP", flags="", src_port=12)
    signals = detector.process(outlier)
    assert len(signals) == 1
    assert signals[0].source == "ml"
    assert signals[0].rule_id == "ML-IFOREST-ANOMALY"
    assert signals[0].severity in ("medium", "high")
    assert "anomaly_score" in signals[0].metadata


def test_in_distribution_packet_is_silent(tmp_path):
    model_path = _train_tmp_model(tmp_path)
    # Tight thresholds so only clear outliers trigger
    cfg = MLDetectorConfig(
        enabled=True, model_path=model_path, high_threshold=-0.9, medium_threshold=-0.8
    )
    detector = MLDetector(cfg)
    detector.initialize()

    normal = _packet(size=120, src_port=50000, dst_port=443)
    assert detector.process(normal) == []


def test_cooldown_suppresses_repeat(tmp_path):
    model_path = _train_tmp_model(tmp_path)
    cfg = MLDetectorConfig(
        enabled=True,
        model_path=model_path,
        high_threshold=0.0,
        medium_threshold=0.5,
        cooldown_sec=60,
    )
    detector = MLDetector(cfg)
    detector.initialize()

    ts = time.time()
    p1 = _packet(timestamp=ts, size=65000, dst_port=1, proto="ICMP", flags="", src_port=12)
    p2 = _packet(timestamp=ts + 5, size=65000, dst_port=1, proto="ICMP", flags="", src_port=12)

    first = detector.process(p1)
    second = detector.process(p2)
    assert len(first) == 1
    assert second == []
