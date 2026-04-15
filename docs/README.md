# NIDS - Network Intrusion Detection System

A production-lite NIDS designed for low-spec hardware (i5 7th gen, 8GB RAM, SSD). Provides real-time network intrusion detection with rate-based rules, gated YARA signatures, and threat intelligence enrichment.

## Features

- **Rate-Based Detection**: Port scans, brute force, SYN flood, ICMP flood, DNS flood, host sweep, data exfiltration
- **Gated YARA Scanning**: Signature-based detection only on suspicious traffic (CPU-efficient)
- **Threat Intelligence**: IP reputation enrichment with AbuseIPDB (cached)
- **Live Dashboard**: Real-time alert feed with severity counters, charts, and filtering
- **REST API**: Query historical alerts and statistics
- **WebSocket**: Real-time alert streaming

## Requirements

- Python 3.10+
- 2+ vCPU, 4GB+ RAM, SSD storage
- Network interface with promiscuous mode (for live capture)
- Root/sudo for packet capture

### Optional Dependencies

- `scapy` - For live packet capture
- `yara-python` - For YARA signature matching
- `aiohttp` - For async HTTP requests (reputation enrichment)

## Installation

```bash
# Clone and install dependencies
cd NIDS
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Install optional dependencies
pip install scapy yara-python
```

## Configuration

Edit `.env` or modify `nids/core/config.py` for:

- Capture interface and BPF filter
- Detection thresholds and windows
- YARA rules file path
- Reputation API key (AbuseIPDB)
- API server host/port

### Environment Variables

```bash
# Required for reputation enrichment
export ABUSEIPDB_API_KEY="your-api-key-here"

# Optional: customize settings
export NIDS_INTERFACE="eth0"
export NIDS_LOG_LEVEL="INFO"
```

## Running

### Quick Start (Demo Mode)

```bash
python main.py
```

This starts:
- Detection pipeline (with mock capture for testing)
- API server on http://localhost:8000
- WebSocket on ws://localhost:8000/ws/alerts

### First Create & Start the venv 

python -m venv venv 
source venv/bin/activate 


### Live Capture Mode

```bash
# Ensure scapy is installed
pip install scapy

# Run with live capture
python main.py
```

The system will capture packets from the configured interface (default: eth0).

### Dashboard

1. Start the NIDS server
2. Open `nids/ui/NIDSDashboard.jsx` in a React environment
3. Or serve it via any static file server

For development:
```bash
# Using a simple HTTP server (from nids/ui directory)
python -m http.server 3000
```

Then open http://localhost:3000

## Testing

```bash
# Run unit tests
pytest tests/

# Run specific test
pytest tests/test_rate_engine.py -v
```

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/v1/alerts` | GET | Get paginated alerts |
| `/api/v1/alerts/{id}` | GET | Get single alert |
| `/api/v1/stats` | GET | Get alert statistics |
| `/api/v1/health` | GET | Health check |
| `/api/v1/ready` | GET | Readiness check |
| `/ws/alerts` | WS | Real-time alert stream |

### Example Queries

```bash
# Get recent alerts
curl http://localhost:8000/api/v1/alerts?limit=10

# Filter by severity
curl http://localhost:8000/api/v1/alerts?severity=high

# Get statistics
curl http://localhost:8000/api/v1/stats
```

## Architecture

See [ARCHITECTURE.md](ARCHITECTURE.md) for system design details.

## Module Reference

See [MODULES.md](MODULES.md) for detailed module documentation.

## Troubleshooting

### Permission Denied

Run with sudo or set appropriate capabilities for packet capture:
```bash
sudo setcap cap_net_raw,cap_net_admin=eip /path/to/python
```

### Database Locked

If using SQLite with multiple processes, ensure proper timeout settings. The default is 5 seconds.

### YARA Not Loading

Ensure `nids_rules.yar` exists in the project root or configured path.

### API Not Responding

Check logs in `nids.log` and ensure port 8000 is available.

## Development

### Project Structure

```
nids/
├── core/           # Core schemas, config, capture, correlation
├── detectors/      # Rate engine, YARA engine
├── enrichment/     # Reputation/threat intel
├── storage/        # SQLite database layer
├── api/            # FastAPI server, WebSocket, endpoints
├── ui/             # React dashboard
├── pipeline.py     # Main pipeline orchestration
└── main.py         # Entry point

docs/               # Documentation
tests/              # Unit tests
```

### Adding Custom Rules

1. Edit `nids_rules.yar` for YARA rules
2. Modify `nids/detectors/rate_engine.py` RULES dict for rate rules

## License

Vault-Tec Standard License - Prepared for the Future!
