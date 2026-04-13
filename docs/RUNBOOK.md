# NIDS Runbook

Operational guide for running and managing the Network Intrusion Detection System.

## Prerequisites

- Python 3.10 or higher
- libpcap development libraries: `sudo apt install libpcap-dev`
- Python dependencies installed in virtual environment ( Poetry or venv )
- (Optional) AbuseIPDB API key for threat intelligence enrichment

## CRITICAL: Python Environment

Always activate your virtual environment before running NIDS commands. Using a different Python than the one with dependencies installed will cause "Module not found" errors.

```bash
# Using Poetry (recommended)
poetry shell
python main.py

# Using venv
source venv/bin/activate
python main.py
```

## Running the NIDS

### Step 1: Start the Backend

Run with sudo (required for raw socket access):

```bash
sudo python main.py
```

The backend will:
- Start packet capture on the configured interface
- Initialize the detection pipeline
- Start the API server on `http://localhost:8000`

### Step 2: Start the Dashboard

In a separate terminal:

```bash
cd dashboard-viewer
npm run dev
```

Open http://localhost:5173 in your browser.

## Triggering Test Alerts

Use the included `generate_nids_alerts.py` script to create test traffic that triggers detection rules.

### Basic Usage

```bash
# Run all attack types once
python generate_nids_alerts.py --target 127.0.0.1

# Run continuously (attack every 30 seconds)
python generate_nids_alerts.py --continuous --interval 30
```

### Specific Attack Types

| Command | Rule ID | Severity | Description |
|---------|--------|----------|-----------|
| `--mode portscan` | RATE-001 | HIGH | Port scan detection |
| `--mode bruteforce` | RATE-002 | HIGH | Brute force auth attempts |
| `--mode synflood` | RATE-003 | CRITICAL | SYN flood DoS |
| `--mode icmpflood` | RATE-004 | MEDIUM | ICMP flood |
| `--mode dnsflood` | RATE-006 | MEDIUM | DNS query flood |
| `--mode sql_injection` | WEB-001 | HIGH | SQL injection (YARA) |
| `--mode xss` | WEB-003 | MEDIUM | XSS attack (YARA) |
| `--mode cmd_injection` | WEB-005 | CRITICAL | Command injection (YARA) |
| `--mode log4shell` | CVE-2021-44228 | CRITICAL | Log4Shell (YARA) |
| `--mode webshell` | MAL-003 | CRITICAL | Webshell upload (YARA) |
| `--mode yara` | (various) | various | All YARA-based attacks |
| `--mode web` | (various) | various | Web attacks only |
| `--mode dos` | (various) | various | DoS attacks only |
| `--mode random` | (various) | various | Random mix of attacks |

### Examples

```bash
# Trigger a port scan alert
python generate_nids_alerts.py --mode portscan --target 127.0.0.1

# Trigger SQL injection alert
python generate_nids_alerts.py --mode sql_injection --target 127.0.0.1

# Continuous mixed traffic for testing
python generate_nids_alerts.py --continuous --mode random --interval 60
```

## Viewing Alerts

### Via REST API

```bash
# Get recent alerts
curl http://localhost:8000/api/v1/alerts?limit=20

# Get statistics
curl http://localhost:8000/api/v1/stats

# Get traffic metrics
curl http://localhost:8000/api/v1/metrics
```

### Via Dashboard

Open http://localhost:5173 in your browser. The dashboard shows:
- Live alert feed (real-time via WebSocket)
- Severity counters (Critical, High, Medium, Low)
- Traffic volume chart (packets per second)
- Top attacking IPs
- Rule hit frequency

## Configuration

### Interface

By default, NIDS uses the interface configured in settings. **Important:** In container/VM environments, `any` interface does not work. Use a specific interface like `lo` (loopback), `eth0`, or `wlan0`.

Find available interfaces:
```bash
ip addr
# or
ip link show
```

### Runtime Profile

- `lite` (default): Optimized for low-spec hardware (i5 7th gen, 8GB RAM)
- `enhanced`: Full features for higher-spec systems

Set via config or environment variable `NIDS_RUNTIME_PROFILE=lite`

### Retention

Alerts are stored in SQLite and automatically cleaned up after the configured retention period (default: 7 days).

To reset:
```bash
# Stop NIDS, then delete the database
rm nids.db
```

## Troubleshooting

### "Module not found" Errors

```bash
# Activate your virtual environment first
poetry shell
# or
source venv/bin/activate
```

### No Packets Captured

1. Check interface name is correct:
   ```bash
   ip addr
   ```
2. Verify interface is up:
   ```bash
   sudo ip link set <interface> up
   ```

### "Interface not found" Error

Use specific interface name instead of `any`. Common options:
- `lo` - loopback (for local testing)
- `eth0` - first ethernet interface
- `wlan0` - wireless interface

### High CPU or Memory

Switch to lite profile:
```bash
export NIDS_RUNTIME_PROFILE=lite
sudo python main.py
```

### No Alerts Generated

Ensure you're generating traffic to the correct target IP:
```bash
# Default target is 127.0.0.1 (loopback)
python generate_nids_alerts.py --target 127.0.0.1 --mode portscan
```

### Dashboard Not Connecting

1. Ensure backend is running: `curl http://localhost:8000/api/v1/health`
2. Ensure dashboard dev server is running: `npm run dev` (in dashboard-viewer/)
3. Check browser console for errors

## Monitoring

### Health Checks

```bash
# API health
curl http://localhost:8000/api/v1/health

# Readiness
curl http://localhost:8000/api/v1/ready
```

### Metrics

```bash
# Real-time traffic metrics
curl http://localhost:8000/api/v1/metrics
```

Response includes:
- `packets_per_sec`: Current packet rate
- `total_packets`: Cumulative packets since start
- `packets_dropped`: Dropped packets count
- `queue_depth`: Current capture queue size

### Logs

Logs are written to `nids.log` in the project directory.

View recent logs:
```bash
tail -f nids.log
```

## Stopping the NIDS

```bash
# Press Ctrl+C in the terminal running main.py
# Or send SIGTERM:
pkill -f "python main.py"
```

## Quick Reference

```bash
# Start NIDS
poetry shell && sudo python main.py

# In another terminal - generate test traffic
python generate_nids_alerts.py --continuous --mode random

# In another terminal - start dashboard
cd dashboard-viewer && npm run dev

# View alerts
curl http://localhost:8000/api/v1/alerts?limit=20

# View metrics
curl http://localhost:8000/api/v1/metrics
```

---

For architecture and module details, see `ARCHITECTURE.md` and `MODULES.md`.
