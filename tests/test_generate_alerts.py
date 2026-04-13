"""
tests/test_generate_alerts.py
Tests for generate_nids_alerts.py script
"""

import pytest
import subprocess
import socket
import time
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

import generate_nids_alerts as gen
from scapy.all import IP, TCP, UDP, ICMP, Raw


def has_root():
    """Check if running as root (for raw socket tests)"""
    import os

    return os.geteuid() == 0


def run_script(args, timeout=30):
    """Run generate_nids_alerts.py script - uses sudo only if not root"""
    import os

    cmd = args
    if not has_root():
        cmd = ["sudo", "-S"] + args
    return subprocess.run(
        cmd, capture_output=True, text=True, timeout=timeout, input=""
    )


@pytest.fixture
def nids_running():
    """Simple check if NIDS API is available on port 8000"""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    result = sock.connect_ex(("localhost", 8000))
    sock.close()
    return result == 0


@pytest.fixture
def target_ip():
    """Default target IP for tests"""
    return "127.0.0.1"


# ==================== Packet Count Tests ====================


def test_port_scan_sends_30_packets(target_ip, monkeypatch):
    """port_scan() should send exactly 30 packets by default"""
    sent_packets = []

    def mock_send(pkt, **kwargs):
        sent_packets.append(pkt)

    monkeypatch.setattr("generate_nids_alerts.send", mock_send)
    gen.port_scan(target_ip, count=30)

    assert len(sent_packets) == 30


def test_brute_force_sends_20_packets(target_ip, monkeypatch):
    """brute_force() should send exactly 20 packets by default"""
    import generate_nids_alerts as gen

    sent_packets = []

    def mock_send(pkt, **kwargs):
        sent_packets.append(pkt)

    monkeypatch.setattr("generate_nids_alerts.send", mock_send)
    gen.brute_force(target_ip, port=22, count=20)

    assert len(sent_packets) == 20


def test_syn_flood_sends_260_packets(target_ip, monkeypatch):
    """syn_flood() should send exactly 260 packets by default"""
    import generate_nids_alerts as gen

    sent_packets = []

    def mock_send(pkt, **kwargs):
        sent_packets.append(pkt)

    monkeypatch.setattr("generate_nids_alerts.send", mock_send)
    gen.syn_flood(target_ip, target_port=80, count=260)

    assert len(sent_packets) == 260


def test_icmp_flood_sends_140_packets(target_ip, monkeypatch):
    """icmp_flood() should send exactly 140 packets by default"""
    import generate_nids_alerts as gen

    sent_packets = []

    def mock_send(pkt, **kwargs):
        sent_packets.append(pkt)

    monkeypatch.setattr("generate_nids_alerts.send", mock_send)
    gen.icmp_flood(target_ip, count=140)

    assert len(sent_packets) == 140


def test_dns_flood_sends_80_packets(target_ip, monkeypatch):
    """dns_flood() should send exactly 80 packets by default"""
    import generate_nids_alerts as gen

    sent_packets = []

    def mock_send(pkt, **kwargs):
        sent_packets.append(pkt)

    monkeypatch.setattr("generate_nids_alerts.send", mock_send)
    gen.dns_flood(target_ip, count=80)

    assert len(sent_packets) == 80


# ==================== YARA Payload Tests ====================


def test_sql_injection_payloads(target_ip, monkeypatch):
    """Payloads should contain SQL injection signatures"""
    payloads_sent = []

    def mock_send(pkt, **kwargs):
        if pkt.haslayer(Raw):
            payloads_sent.append(str(pkt[Raw].load))

    monkeypatch.setattr("generate_nids_alerts.send", mock_send)
    gen.sql_injection(target_ip, count=1)

    payload_text = "".join(payloads_sent)
    assert "' OR '1'='1" in payload_text
    assert "UNION SELECT" in payload_text
    assert "admin'--" in payload_text


def test_xss_payloads(target_ip, monkeypatch):
    """Payloads should contain XSS signatures"""
    import generate_nids_alerts as gen

    payloads_sent = []

    def mock_send(pkt, **kwargs):
        if pkt.haslayer(gen.Raw):
            payloads_sent.append(str(pkt[gen.Raw].load))

    monkeypatch.setattr("generate_nids_alerts.send", mock_send)
    gen.xss_attack(target_ip, count=1)

    payload_text = "".join(payloads_sent)
    assert "<script>" in payload_text
    assert "javascript:" in payload_text
    assert "onerror=" in payload_text


def test_cmd_injection_payloads(target_ip, monkeypatch):
    """Payloads should contain command injection signatures"""
    import generate_nids_alerts as gen

    payloads_sent = []

    def mock_send(pkt, **kwargs):
        if pkt.haslayer(gen.Raw):
            payloads_sent.append(str(pkt[gen.Raw].load))

    monkeypatch.setattr("generate_nids_alerts.send", mock_send)
    gen.cmd_injection(target_ip, count=1)

    payload_text = "".join(payloads_sent)
    assert "; cat" in payload_text or "cat /etc" in payload_text
    assert "| ls" in payload_text or "ls -la" in payload_text
    assert "`id`" in payload_text or "$(whoami)" in payload_text


def test_log4shell_payloads(target_ip, monkeypatch):
    """Payloads should contain JNDI exploitation patterns"""
    import generate_nids_alerts as gen

    payloads_sent = []

    def mock_send(pkt, **kwargs):
        if pkt.haslayer(gen.Raw):
            payloads_sent.append(str(pkt[gen.Raw].load))

    monkeypatch.setattr("generate_nids_alerts.send", mock_send)
    gen.log4shell(target_ip, count=1)

    payload_text = "".join(payloads_sent)
    assert "${jndi:" in payload_text


def test_webshell_payloads(target_ip, monkeypatch):
    """Payloads should contain webshell signatures"""
    import generate_nids_alerts as gen

    payloads_sent = []

    def mock_send(pkt, **kwargs):
        if pkt.haslayer(gen.Raw):
            payloads_sent.append(str(pkt[gen.Raw].load))

    monkeypatch.setattr("generate_nids_alerts.send", mock_send)
    gen.webshell(target_ip, count=1)

    payload_text = "".join(payloads_sent)
    assert "eval(" in payload_text or "base64_decode" in payload_text
    assert (
        "system(" in payload_text
        or "passthru(" in payload_text
        or "shell_exec(" in payload_text
    )


# ==================== Target IP Tests ====================


def test_rate_attacks_use_target_ip(target_ip, monkeypatch):
    """All rate attacks should use the specified target IP"""
    import generate_nids_alerts as gen
    from scapy.all import IP

    target_ips = []

    def mock_send(pkt, **kwargs):
        if pkt.haslayer(IP):
            target_ips.append(pkt[IP].dst)

    monkeypatch.setattr("generate_nids_alerts.send", mock_send)

    gen.port_scan(target_ip, count=5)
    gen.brute_force(target_ip, port=22, count=3)
    gen.syn_flood(target_ip, count=5)
    gen.icmp_flood(target_ip, count=3)
    gen.dns_flood(target_ip, count=3)

    for ip in target_ips:
        assert ip == target_ip


def test_yara_payloads_include_target(target_ip, monkeypatch):
    """YARA payloads should include target IP in Host header"""
    import generate_nids_alerts as gen

    payloads_sent = []

    def mock_send(pkt, **kwargs):
        if pkt.haslayer(gen.Raw):
            payloads_sent.append(str(pkt[gen.Raw].load))

    monkeypatch.setattr("generate_nids_alerts.send", mock_send)
    gen.sql_injection(target_ip, count=1)

    payload_text = "".join(payloads_sent)
    assert target_ip in payload_text


# ==================== Protocol/Port Tests ====================


def test_syn_flood_uses_tcp(target_ip, monkeypatch):
    """SYN flood should use TCP protocol"""
    import generate_nids_alerts as gen
    from scapy.all import TCP

    protocols = []

    def mock_send(pkt, **kwargs):
        if pkt.haslayer(TCP):
            protocols.append("TCP")

    monkeypatch.setattr("generate_nids_alerts.send", mock_send)
    gen.syn_flood(target_ip, count=5)

    assert "TCP" in protocols


def test_syn_flood_uses_port_80(target_ip, monkeypatch):
    """SYN flood should use port 80 by default"""
    import generate_nids_alerts as gen
    from scapy.all import TCP

    ports = []

    def mock_send(pkt, **kwargs):
        if pkt.haslayer(TCP):
            ports.append(pkt[TCP].dport)

    monkeypatch.setattr("generate_nids_alerts.send", mock_send)
    gen.syn_flood(target_ip, count=5)

    for port in ports:
        assert port == 80


def test_brute_force_targets_port_22(target_ip, monkeypatch):
    """Brute force should target port 22 by default"""
    import generate_nids_alerts as gen
    from scapy.all import TCP

    ports = []

    def mock_send(pkt, **kwargs):
        if pkt.haslayer(TCP):
            ports.append(pkt[TCP].dport)

    monkeypatch.setattr("generate_nids_alerts.send", mock_send)
    gen.brute_force(target_ip, port=22, count=5)

    for port in ports:
        assert port == 22


def test_log4shell_targets_port_8080(target_ip, monkeypatch):
    """Log4Shell should target port 8080"""
    import generate_nids_alerts as gen
    from scapy.all import TCP

    ports = []

    def mock_send(pkt, **kwargs):
        if pkt.haslayer(TCP):
            ports.append(pkt[TCP].dport)

    monkeypatch.setattr("generate_nids_alerts.send", mock_send)
    gen.log4shell(target_ip, count=1)

    for port in ports:
        assert port == 8080


def test_icmp_flood_uses_icmp(target_ip, monkeypatch):
    """ICMP flood should use ICMP protocol"""
    import generate_nids_alerts as gen
    from scapy.all import ICMP

    protocols = []

    def mock_send(pkt, **kwargs):
        if pkt.haslayer(ICMP):
            protocols.append("ICMP")

    monkeypatch.setattr("generate_nids_alerts.send", mock_send)
    gen.icmp_flood(target_ip, count=5)

    assert "ICMP" in protocols


def test_dns_flood_uses_udp_port_53(target_ip, monkeypatch):
    """DNS flood should use UDP on port 53"""
    import generate_nids_alerts as gen
    from scapy.all import UDP

    protocols = []
    ports = []

    def mock_send(pkt, **kwargs):
        if pkt.haslayer(UDP):
            protocols.append("UDP")
            ports.append(pkt[UDP].dport)

    monkeypatch.setattr("generate_nids_alerts.send", mock_send)
    gen.dns_flood(target_ip, count=5)

    assert "UDP" in protocols
    for port in ports:
        assert port == 53


# ==================== Argument Parsing Tests ====================


# ==================== Argument Parsing Tests ====================


@pytest.mark.skipif(not has_root(), reason="Requires root for raw sockets")
def test_mode_portscan():
    """--mode portscan should execute port_scan"""
    result = run_script(
        [
            sys.executable,
            "generate_nids_alerts.py",
            "--mode",
            "portscan",
            "--target",
            "127.0.0.1",
        ]
    )
    assert result.returncode == 0
    assert "Port Scan" in result.stdout


@pytest.mark.skipif(not has_root(), reason="Requires root for raw sockets")
def test_mode_bruteforce():
    """--mode bruteforce should execute brute_force"""
    result = run_script(
        [
            sys.executable,
            "generate_nids_alerts.py",
            "--mode",
            "bruteforce",
            "--target",
            "127.0.0.1",
        ]
    )
    assert result.returncode == 0
    assert "Brute Force" in result.stdout


@pytest.mark.skipif(not has_root(), reason="Requires root for raw sockets")
def test_mode_synflood():
    """--mode synflood should execute syn_flood"""
    result = run_script(
        [
            sys.executable,
            "generate_nids_alerts.py",
            "--mode",
            "synflood",
            "--target",
            "127.0.0.1",
        ]
    )
    assert result.returncode == 0
    assert "SYN Flood" in result.stdout


@pytest.mark.skipif(not has_root(), reason="Requires root for raw sockets")
def test_mode_icmpflood():
    """--mode icmpflood should execute icmp_flood"""
    result = run_script(
        [
            sys.executable,
            "generate_nids_alerts.py",
            "--mode",
            "icmpflood",
            "--target",
            "127.0.0.1",
        ]
    )
    assert result.returncode == 0
    assert "ICMP Flood" in result.stdout


@pytest.mark.skipif(not has_root(), reason="Requires root for raw sockets")
def test_mode_dnsflood():
    """--mode dnsflood should execute dns_flood"""
    result = run_script(
        [
            sys.executable,
            "generate_nids_alerts.py",
            "--mode",
            "dnsflood",
            "--target",
            "127.0.0.1",
        ]
    )
    assert result.returncode == 0
    assert "DNS Flood" in result.stdout


@pytest.mark.skipif(not has_root(), reason="Requires root for raw sockets")
def test_mode_sql_injection():
    """--mode sql_injection should execute sql_injection"""
    result = run_script(
        [
            sys.executable,
            "generate_nids_alerts.py",
            "--mode",
            "sql_injection",
            "--target",
            "127.0.0.1",
        ]
    )
    assert result.returncode == 0
    assert "SQL Injection" in result.stdout


@pytest.mark.skipif(not has_root(), reason="Requires root for raw sockets")
def test_mode_xss():
    """--mode xss should execute xss_attack"""
    result = run_script(
        [
            sys.executable,
            "generate_nids_alerts.py",
            "--mode",
            "xss",
            "--target",
            "127.0.0.1",
        ]
    )
    assert result.returncode == 0
    assert "XSS" in result.stdout


@pytest.mark.skipif(not has_root(), reason="Requires root for raw sockets")
def test_mode_cmd_injection():
    """--mode cmd_injection should execute cmd_injection"""
    result = run_script(
        [
            sys.executable,
            "generate_nids_alerts.py",
            "--mode",
            "cmd_injection",
            "--target",
            "127.0.0.1",
        ]
    )
    assert result.returncode == 0
    assert "Command Injection" in result.stdout


@pytest.mark.skipif(not has_root(), reason="Requires root for raw sockets")
def test_mode_log4shell():
    """--mode log4shell should execute log4shell"""
    result = run_script(
        [
            sys.executable,
            "generate_nids_alerts.py",
            "--mode",
            "log4shell",
            "--target",
            "127.0.0.1",
        ]
    )
    assert result.returncode == 0
    assert "Log4Shell" in result.stdout


@pytest.mark.skipif(not has_root(), reason="Requires root for raw sockets")
def test_mode_webshell():
    """--mode webshell should execute webshell"""
    result = run_script(
        [
            sys.executable,
            "generate_nids_alerts.py",
            "--mode",
            "webshell",
            "--target",
            "127.0.0.1",
        ]
    )
    assert result.returncode == 0
    assert "Webshell" in result.stdout


@pytest.mark.skipif(not has_root(), reason="Requires root for raw sockets")
def test_mode_yara():
    """--mode yara should execute all YARA attacks"""
    result = run_script(
        [
            sys.executable,
            "generate_nids_alerts.py",
            "--mode",
            "yara",
            "--target",
            "127.0.0.1",
        ]
    )
    assert result.returncode == 0
    assert "SQL Injection" in result.stdout
    assert "XSS" in result.stdout
    assert "Command Injection" in result.stdout


@pytest.mark.skipif(not has_root(), reason="Requires root for raw sockets")
def test_mode_web():
    """--mode web should execute web attacks"""
    result = run_script(
        [
            sys.executable,
            "generate_nids_alerts.py",
            "--mode",
            "web",
            "--target",
            "127.0.0.1",
        ]
    )
    assert result.returncode == 0
    assert "SQL Injection" in result.stdout
    assert "XSS" in result.stdout
    assert "Command Injection" in result.stdout


@pytest.mark.skipif(not has_root(), reason="Requires root for raw sockets")
def test_mode_dos():
    """--mode dos should execute DoS attacks"""
    result = run_script(
        [
            sys.executable,
            "generate_nids_alerts.py",
            "--mode",
            "dos",
            "--target",
            "127.0.0.1",
        ]
    )
    assert result.returncode == 0
    assert "SYN Flood" in result.stdout
    assert "ICMP Flood" in result.stdout
    assert "DNS Flood" in result.stdout


@pytest.mark.skipif(not has_root(), reason="Requires root for raw sockets")
def test_mode_random():
    """--mode random should select attacks randomly"""
    result = run_script(
        [
            sys.executable,
            "generate_nids_alerts.py",
            "--mode",
            "random",
            "--target",
            "127.0.0.1",
        ]
    )
    assert result.returncode == 0
    assert "Randomly selected" in result.stdout


@pytest.mark.skipif(not has_root(), reason="Requires root for raw sockets")
def test_mode_all():
    """--mode all should execute all attacks"""
    result = run_script(
        [
            sys.executable,
            "generate_nids_alerts.py",
            "--mode",
            "all",
            "--target",
            "127.0.0.1",
        ]
    )
    assert result.returncode == 0
    assert "Port Scan" in result.stdout
    assert "Brute Force" in result.stdout
    assert "SYN Flood" in result.stdout


# ==================== Continuous Mode Tests ====================


@pytest.mark.skipif(not has_root(), reason="Requires root for raw sockets")
def test_continuous_runs_multiple_rounds():
    """--continuous with --count should run specified rounds"""
    result = subprocess.run(
        [
            sys.executable,
            "generate_nids_alerts.py",
            "--continuous",
            "--count",
            "2",
            "--interval",
            "1",
        ],
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert result.returncode == 0
    assert "Round 1" in result.stdout
    assert "Round 2" in result.stdout


@pytest.mark.skipif(not has_root(), reason="Requires root for raw sockets")
def test_continuous_respects_interval():
    """--continuous should respect --interval argument"""
    import time

    start = time.time()
    result = subprocess.run(
        [
            sys.executable,
            "generate_nids_alerts.py",
            "--continuous",
            "--count",
            "1",
            "--interval",
            "2",
        ],
        capture_output=True,
        text=True,
        timeout=60,
    )
    elapsed = time.time() - start
    assert elapsed >= 1


# ==================== End-to-End Tests ====================


@pytest.mark.skipif(True, reason="Requires NIDS running on port 8000")
def test_e2e_portscan_triggers_alert(nids_running):
    """Port scan should trigger RATE-001 alert"""
    if not nids_running:
        pytest.skip("NIDS not running")

    import requests

    subprocess.run(
        [
            sys.executable,
            "generate_nids_alerts.py",
            "--mode",
            "portscan",
            "--target",
            "127.0.0.1",
        ],
        capture_output=True,
    )
    time.sleep(2)

    resp = requests.get("http://localhost:8000/api/v1/alerts?limit=10")
    alerts = resp.json()["alerts"]

    rule_ids = [a["rule_ids"] for a in alerts]
    assert any("RATE-001" in r for r in rule_ids)


@pytest.mark.skipif(True, reason="Requires NIDS running on port 8000")
def test_e2e_bruteforce_triggers_alert(nids_running):
    """Brute force should trigger RATE-002 alert"""
    if not nids_running:
        pytest.skip("NIDS not running")

    import requests

    subprocess.run(
        [
            sys.executable,
            "generate_nids_alerts.py",
            "--mode",
            "bruteforce",
            "--target",
            "127.0.0.1",
        ],
        capture_output=True,
    )
    time.sleep(2)

    resp = requests.get("http://localhost:8000/api/v1/alerts?limit=10")
    alerts = resp.json()["alerts"]

    rule_ids = [a["rule_ids"] for a in alerts]
    assert any("RATE-002" in r for r in rule_ids)


@pytest.mark.skipif(True, reason="Requires NIDS running on port 8000")
def test_e2e_icmpflood_triggers_alert(nids_running):
    """ICMP flood should trigger RATE-004 alert"""
    if not nids_running:
        pytest.skip("NIDS not running")

    import requests

    subprocess.run(
        [
            sys.executable,
            "generate_nids_alerts.py",
            "--mode",
            "icmpflood",
            "--target",
            "127.0.0.1",
        ],
        capture_output=True,
    )
    time.sleep(2)

    resp = requests.get("http://localhost:8000/api/v1/alerts?limit=10")
    alerts = resp.json()["alerts"]

    rule_ids = [a["rule_ids"] for a in alerts]
    assert any("RATE-004" in r for r in rule_ids)


@pytest.mark.skipif(True, reason="Requires NIDS running on port 8000")
def test_e2e_sql_injection_triggers_alert(nids_running):
    """SQL injection should trigger WEB-001 alert"""
    if not nids_running:
        pytest.skip("NIDS not running")

    import requests

    subprocess.run(
        [
            sys.executable,
            "generate_nids_alerts.py",
            "--mode",
            "sql_injection",
            "--target",
            "127.0.0.1",
        ],
        capture_output=True,
    )
    time.sleep(2)

    resp = requests.get("http://localhost:8000/api/v1/alerts?limit=10")
    alerts = resp.json()["alerts"]

    rule_ids = [a["rule_ids"] for a in alerts]
    assert any("WEB-001" in r for r in rule_ids)
