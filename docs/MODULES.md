# NIDS Module Documentation

## Core Modules

### nids.core.config

**Purpose**: Centralized configuration management

**Key Classes**:
- `Settings`: Main settings using Pydantic BaseSettings
- `DatabaseConfig`, `CaptureConfig`, `RateDetectorConfig`, etc.

**Usage**:
```python
from nids.core.config import get_settings

settings = get_settings()
print(settings.rate_detector.port_scan_threshold)
```

**Environment Variables**:
- `NIDS_INTERFACE`: Capture interface (default: eth0)
- `NIDS_LOG_LEVEL`: Log level (default: INFO)
- `ABUSEIPDB_API_KEY`: API key for reputation checks

---

### nids.core.schemas

**Purpose**: Canonical data structures for NIDS data flow

**Key Classes**:
- `PacketEvent`: Normalized packet metadata
- `SignalEvent`: Detection signal from a single engine
- `AlertEvent`: Correlated alert from multiple signals
- `Severity`: Enum for severity levels
- `Protocol`: Enum for network protocols

**Usage**:
```python
from nids.core.schemas import PacketEvent, SignalEvent, AlertEvent

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
```

---

### nids.core.capture

**Purpose**: Packet capture with bounded queue

**Key Classes**:
- `PacketCapture`: Base capture class
- `ScapyCapture`: Scapy-based live capture
- `CaptureStats`: Statistics container

**Usage**:
```python
from nids.core.capture import ScapyCapture

capture = ScapyCapture(
    interface="eth0",
    bpf_filter="ip and tcp",
    queue_maxsize=1000,
)
capture.set_callback(my_processor)
capture.start()
```

---

### nids.core.correlation

**Purpose**: Alert correlation and scoring

**Key Classes**:
- `AlertCorrelator`: Main correlator
- `SignalGroup`: Group of related signals

**Usage**:
```python
from nids.core.correlation import AlertCorrelator
from nids.core.config import get_settings

correlator = AlertCorrelator(get_settings().correlator)
alerts = correlator.process_signals(signals)
```

---

## Detection Modules

### nids.detectors.rate_engine

**Purpose**: Rate-based anomaly detection using sliding windows

**Detection Rules**:
| Rule ID | Name | Threshold | Window |
|---------|------|-----------|--------|
| RATE-001 | Port Scan | 20 unique ports | 10s |
| RATE-002 | Brute Force | 15 attempts | 30s |
| RATE-003 | SYN Flood | 200 packets | 5s |
| RATE-004 | ICMP Flood | 100 packets | 5s |
| RATE-005 | Host Sweep | 10 unique hosts | 15s |
| RATE-006 | DNS Flood | 50 queries | 5s |
| RATE-007 | Exfiltration | 5 MB | 60s |

**Key Classes**:
- `RateDetector`: Main detector
- `SlidingWindow`: Time-based counter
- `SetWindow`: Unique value tracker

**Usage**:
```python
from nids.detectors.rate_engine import RateDetector
from nids.core.schemas import PacketEvent

detector = RateDetector()
signals = detector.process(packet)
```

---

### nids.detectors.yara_engine

**Purpose**: YARA signature-based detection

**Key Classes**:
- `YaraDetector`: YARA engine with gating

**Features**:
- Compiles `nids_rules.yar` at startup
- Gated scanning (only suspicious traffic)
- Timeout protection (1s default)
- Max payload size limit (1MB default)

**Usage**:
```python
from nids.detectors.yara_engine import YaraDetector

detector = YaraDetector(
    rules_file="nids_rules.yar",
    gating_enabled=True,
)
detector.initialize()
signals = detector.process(packet)
```

---

## Enrichment Modules

### nids.enrichment.reputation

**Purpose**: Threat intelligence enrichment

**Key Classes**:
- `ReputationEngine`: Main enrichment engine
- `ReputationResult`: Result data class
- `ReputationWorker`: Async background worker

**Features**:
- AbuseIPDB integration
- SQLite caching with TTL
- Async HTTP with timeout/retry
- Only enriches medium+ severity signals

**Usage**:
```python
from nids.enrichment.reputation import ReputationEngine

engine = ReputationEngine(
    provider="abuseipdb",
    api_key="your-key",
    cache_ttl_sec=3600,
)
engine.set_database(db)

# Async enrichment
enriched = await engine.enrich(signal)
```

---

## Storage Modules

### nids.storage.database

**Purpose**: SQLite database layer

**Key Classes**:
- `Database`: Main database interface

**Tables**:
- `signals`: Detection signals
- `alerts`: Correlated alerts
- `reputation_cache`: IP reputation cache

**Usage**:
```python
from nids.storage.database import get_database

db = get_database("nids.db", retention_days=14)
db.insert_alert(alert)
alerts = db.get_alerts(limit=10, severity="high")
```

**Methods**:
- `insert_signal(signal)`: Store signal
- `insert_alert(alert)`: Store alert
- `get_alerts(...)`: Query with filters
- `get_alert_counts_by_severity()`: Get counts
- `get_top_attacking_ips(limit)`: Get top IPs
- `get_rule_hit_counts(limit)`: Get rule frequency
- `cleanup_old_data()`: Remove old records

---

## API Modules

### nids.api.server

**Purpose**: FastAPI application factory

**Usage**:
```python
from nids.api.server import create_app

app = create_app()
# Run with uvicorn
```

**WebSocket**:
- Endpoint: `/ws/alerts`
- Broadcasts new alerts in real-time

---

### nids.api.alerts

**Purpose**: Alert REST endpoints

**Endpoints**:
- `GET /api/v1/alerts`: List alerts (paginated)
- `GET /api/v1/alerts/{id}`: Get single alert
- `GET /api/v1/stats`: Get statistics

**Query Parameters**:
- `limit`: Max results (default: 100)
- `offset`: Pagination offset
- `severity`: Filter by severity
- `src_ip`: Filter by source IP
- `rule_id`: Filter by rule
- `since`: Filter by timestamp

---

### nids.api.health

**Purpose**: Health check endpoints

**Endpoints**:
- `GET /api/v1/health`: Basic health check
- `GET /api/v1/ready`: Readiness with dependency checks

---

## Pipeline

### nids.pipeline

**Purpose**: Main NIDS pipeline orchestration

**Key Classes**:
- `NIDSPipeline`: Orchestrates all components
- `PipelineStats`: Statistics container

**Usage**:
```python
from nids.pipeline import get_pipeline

pipeline = get_pipeline()
pipeline.start()

stats = pipeline.get_stats()
pipeline.stop()
```

---

## UI Module

### nids.ui.NIDSDashboard

**Purpose**: React dashboard component

**Features**:
- Live alert feed via WebSocket
- Severity counters
- Top attacking IPs chart
- Rule hit frequency
- Severity filtering

**Integration**:
- Connects to `http://localhost:8000/api/v1`
- WebSocket at `ws://localhost:8000/ws/alerts`
- Falls back to mock data if API unavailable

---

## Configuration Reference

### Rate Detector Defaults

```python
{
    "port_scan_threshold": 20,
    "port_scan_window_sec": 10,
    "brute_force_threshold": 15,
    "brute_force_window_sec": 30,
    "syn_flood_threshold": 200,
    "syn_flood_window_sec": 5,
    "icmp_flood_threshold": 100,
    "icmp_flood_window_sec": 5,
    "host_sweep_threshold": 10,
    "host_sweep_window_sec": 15,
    "dns_flood_threshold": 50,
    "dns_flood_window_sec": 5,
    "exfil_threshold_bytes": 5_000_000,
    "exfil_window_sec": 60,
    "cooldown_sec": 60,
}
```

### Correlator Defaults

```python
{
    "dedup_window_sec": 300,
    "score_weights": {
        "rate": 30,
        "yara": 50,
        "reputation": 40,
    },
    "severity_thresholds": {
        "critical": 100,
        "high": 70,
        "medium": 40,
        "low": 10,
    },
}
```