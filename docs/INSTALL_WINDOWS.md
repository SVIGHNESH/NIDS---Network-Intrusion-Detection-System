# Windows Installation Guide

This guide covers installing and running the NIDS on Windows 10 and Windows 11.

## Prerequisites

### 1. Windows Version
- Windows 10 (version 1903 or later)
- Windows 11

### 2. Python
- Python 3.10 or higher
- Download from: https://www.python.org/downloads/
- **Important:** Check "Add Python to PATH" during installation

### 3. Npcap (Required for packet capture)
- Download from: https://nmap.org/npcap/
- Run the installer as Administrator
- Choose "Install Npcap" (not "Install WinPcap")
- Ensure "Install with Npcap SDK" is checked

### 4. Node.js (For dashboard)
- Download from: https://nodejs.org/
- LTS version recommended (18.x or later)

---

## Installation

### Step 1: Install Npcap

1. Download Npcap from https://nmap.org/npcap/
2. Right-click the installer → "Run asAdministrator"
3. Accept the license
4. Check "Install with npcap SDK"
5. Click "Install"
6. Restart computer if prompted

### Step 2: Install Python Dependencies

Open PowerShell as Administrator and run:

```powershell
# Navigate to the NIDS directory
cd C:\path\to\NIDS

# Create virtual environment (optional but recommended)
python -m venv venv

# Activate virtual environment
.\venv\Scripts\Activate

# Install dependencies
pip install -r requirements.txt
```

### Step 3: Install Node.js Dependencies (for dashboard)

```powershell
# Navigate to dashboard directory
cd dashboard-viewer

# Install dependencies
npm install
```

---

## Running the NIDS

### Important: Run as Administrator

Windows requires Administrator privileges for raw packet capture.

**Method 1: From PowerShell (as Administrator)**
```powershell
# Activate virtual environment
.\venv\Scripts\Activate


# Run the NIDS
python main.py
```

**Method 2: From Command Prompt (as Administrator)**
```cmd
venv\Scripts\python.exe main.py
```

### Finding Your Network Interface

Windows uses different interface names than Linux:

| Linux | Windows |
|-------|---------|
| `lo` | `Loopback` |
| `eth0` | `Ethernet` |
| `wlan0` | `Wi-Fi` |

To list available interfaces:

```powershell
python -c "from scapy.all import *; print(get_if_list())"
```

### Configuring the Interface

Edit `config.yaml` or use environment variable:

```powershell
$env:NIDS_INTERFACE = "Loopback"  # For local testing
# or
$env:NIDS_INTERFACE = "Ethernet"  # For physical interface
```

---

## Testing the Installation

### Verify Npcap Installation

```powershell
python -c "from scapy.all import *; print('Scapy OK')"
```

### Generate Test Alerts

```powershell
# Run as Administrator
python generate_nids_alerts.py --mode portscan --target 127.0.0.1
```

### View Alerts

```powershell
curl http://localhost:8000/api/v1/alerts?limit=20
```

### Run Dashboard

```powershell
cd dashboard-viewer
npm run dev
```

Open http://localhost:5173 in your browser.

---

## Common Issues

### "Permission denied" when starting capture

**Cause:** Not running as Administrator

**Solution:** Right-click PowerShell → "Run asAdministrator"

### "No packets captured"

**Cause:** Wrong interface name

**Solution:** 
1. List interfaces:
   ```powershell
   python -c "from scapy.all import *; print(get_if_list())"
   ```
2. Set correct interface in config:
   ```powershell
   $env:NIDS_INTERFACE = "Ethernet"
   ```

### "Npcap not found"

**Cause:** Npcap not installed

**Solution:**
1. Download from https://nmap.org/npcap/
2. Run installer as Administrator
3. Reinstall if issues persist

### "Module not found" errors

**Cause:** Virtual environment not activated

**Solution:**
```powershell
.\venv\Scripts\Activate
```

### Dashboard won't connect

**Cause:** Backend not running

**Solution:** Ensure NIDS is running first, then start dashboard in separate terminal

---

## Quick Reference

```powershell
# Activate virtual environment
.\venv\Scripts\Activate

# Run NIDS (as Administrator)
python main.py

# Generate test alerts (as Administrator)
python generate_nids_alerts.py --mode random --target 127.0.0.1

# Run dashboard
cd dashboard-viewer
npm run dev

# View alerts
curl http://localhost:8000/api/v1/alerts

# Run tests
python -m pytest tests/test_generate_alerts.py -v
```

---

## Differences from Linux

| Feature | Linux | Windows |
|---------|-------|---------|
| Run with | `sudo python main.py` | Run PowerShell as Administrator |
| Interface | `eth0`, `wlan0`, `lo` | `Ethernet`, `Wi-Fi`, `Loopback` |
| Packet library | libpcap | Npcap |
| Terminal | bash | PowerShell/CMD |
| Path separator | `/` | `\` or `/` (Python handles both) |

---

For architecture details, see `ARCHITECTURE.md`.

For modules documentation, see `MODULES.md`.

For operational runbook, see `RUNBOOK.md`.
