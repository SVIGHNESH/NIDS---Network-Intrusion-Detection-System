# NIDS Architecture

## System Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                        Network Traffic                          │
└─────────────────────────────────────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────┐
│                    Packet Capture Layer                         │
│  ┌─────────────────┐  ┌──────────────────────────────────────┐ │
│  │   Scapy Capture │  │  BPF Filter + Bounded Queue          │ │
│  │   (live/replay) │  │  (metadata-only, non-blocking)       │ │
│  └─────────────────┘  └──────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────┐
│                     Detection Engines                           │
│  ┌────────────────┐  ┌───────────────┐  ┌────────────────────┐  │
│  │ Rate Detector │  │ YARA Detector │  │ Reputation Engine │  │
│  │ (sliding wins) │  │ (gated scan)  │  │ (async, cached)   │  │
│  └────────────────┘  └───────────────┘  └────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────┐
│                    Alert Correlator                             │
│  ┌─────────────┐  ┌───────────────┐  ┌──────────────────────┐  │
│  │ Dedup Cache│  │ Score Calculator│  │ Severity Mapper     │  │
│  └─────────────┘  └───────────────┘  └────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
                                │
                    ┌───────────┴───────────┐
                    ▼                       ▼
        ┌──────────────────┐     ┌──────────────────┐
        │   SQLite DB     │     │  WebSocket      │
        │ (alerts/signals)│     │ (live stream)   │
        └──────────────────┘     └──────────────────┘
                    │                       │
                    ▼                       ▼
        ┌──────────────────┐     ┌──────────────────┐
        │   REST API       │     │   Dashboard UI   │
        │ (query/stats)    │     │ (React/Recharts) │
        └──────────────────┘     └──────────────────┘
```

## Component Descriptions

### 1. Packet Capture Layer

**Purpose**: Collect network packets with minimal overhead

**Components**:
- `ScapyCapture`: Live packet capture with BPF filtering
- `PacketCapture`: Base class with bounded queue
- BPF filter (Berkeley Packet Filters): Pre-filter to reduce noise (IP + TCP/UDP/ICMP)

**Design Decisions**:
- Metadata-first: Only extract essential fields (IPs, ports, proto, flags, size)
- Bounded queue prevents memory exhaustion under load
- Non-blocking design: capture never stalls on slow processing

### 2. Detection Engines

#### Rate Detector
**Purpose**: Detect volumetric attacks using sliding windows

**Detection Types**:
- Port Scan (RATE-001): Multiple unique ports from single source
- Brute Force (RATE-002): Multiple auth attempts to same target
- SYN Flood (RATE-003): High SYN packet rate
- ICMP Flood (RATE-004): High ICMP packet rate
- Host Sweep (RATE-005): Multiple unique destinations
- DNS Flood (RATE-006): High DNS query rate
- Exfiltration (RATE-007): Abnormal outbound bytes

**Implementation**:
- SlidingWindow: O(1) add, O(n) count with lazy eviction
- SetWindow: Tracks unique values within time window
- Per-entity state: Dictionary keyed by src_ip or (src,dst) pair

#### YARA Detector
**Purpose**: Signature-based payload analysis

**Design**:
- Gated scanning: Only scan suspicious ports/traffic
- Timeout protection: Max scan time 1s
- Size limits: Max payload 1MB

**Gating Strategy**:
- Scan: 22, 23, 25, 80, 443, 445, 3306, 3389, 5432, 8080
- Plus any HTTP/HTTPS traffic

#### Reputation Engine
**Purpose**: Enrich alerts with threat intelligence

**Provider**: AbuseIPDB (extensible)

**Features**:
- Async HTTP with timeout/retry
- TTL cache in SQLite
- Only checks medium+ severity signals

### 3. Alert Correlator

**Purpose**: Merge signals into actionable alerts

**Features**:
- Deduplication: Per (rule_id, src_ip, dst_ip, port) within window
- Scoring: Base severity + signal contribution + source weight
- Severity mapping: Configurable score thresholds

**Score Calculation**:
```
score = base_severity + signal_contribution + source_weight
severity = mapped from score thresholds
```

### 4. Storage Layer

**Database**: SQLite with WAL mode

**Tables**:
- `signals`: Raw detection signals
- `alerts`: Correlated alerts
- `reputation_cache`: IP reputation cache

**Features**:
- Retention cleanup (configurable days)
- Indexed queries (timestamp, severity, src_ip, rule_id)

### 5. API & WebSocket

**REST API**:
- `/alerts`: Paginated query with filters
- `/stats`: Aggregated statistics
- `/health`, `/ready`: Health checks

**WebSocket**:
- `/ws/alerts`: Real-time alert broadcast

### 6. Dashboard

**Features**:
- Live alert feed with severity badges
- Severity counters
- Top attacking IPs chart
- Rule hit frequency
- Severity/time filtering

**Implementation**: React + Recharts

## Data Flow

```
Packet → Capture Queue → Rate Engine → Signals
                               ↓
                         YARA Engine → Signals
                               ↓
                    Reputation Enrichment → Enriched Signals
                               ↓
                         Correlator → Alerts
                               ↓
                    ┌──────────┴──────────┐
                    ↓                     ↓
              SQLite DB              WebSocket
                    ↓                     ↓
              REST API               Dashboard
```

## Configuration

All thresholds and settings in `nids/core/config.py`:

- Capture: interface, BPF, queue size
- Rate: threshold, window, cooldown per rule
- YARA: rules file, timeout, gating
- Reputation: provider, cache TTL, timeout
- Correlator: dedup window, score weights, severity thresholds

## Performance Considerations

- Bounded queues prevent memory bloat
- Gated YARA reduces CPU on low-spec
- Async reputation doesn't block detection
- WAL mode SQLite for concurrent reads
- Configurable degradation: disable YARA/reputation under load
