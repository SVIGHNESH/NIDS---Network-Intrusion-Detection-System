"""
nids/detectors/rate_engine.py
Rate-based detection engine using sliding windows
"""

import time
import uuid
import logging
from collections import defaultdict, deque
from typing import List, Optional

from nids.core.schemas import PacketEvent, SignalEvent, Severity
from nids.core.config import RateDetectorConfig


logger = logging.getLogger("nids.detectors.rate")


class SlidingWindow:
    """Tracks timestamps within a rolling time window"""

    def __init__(self, window_sec: int):
        self.window_sec = window_sec
        self._events: deque = deque()

    def add(self, ts: float) -> None:
        self._events.append(ts)

    def count(self, now: float) -> int:
        cutoff = now - self.window_sec
        while self._events and self._events[0] < cutoff:
            self._events.popleft()
        return len(self._events)

    def reset(self) -> None:
        self._events.clear()


class SetWindow:
    """Tracks unique values within a rolling time window"""

    def __init__(self, window_sec: int):
        self.window_sec = window_sec
        self._events: deque = deque()

    def add(self, ts: float, value) -> None:
        self._events.append((ts, value))

    def unique_count(self, now: float) -> int:
        cutoff = now - self.window_sec
        while self._events and self._events[0][0] < cutoff:
            self._events.popleft()
        return len({v for _, v in self._events})

    def values(self, now: float) -> set:
        cutoff = now - self.window_sec
        while self._events and self._events[0][0] < cutoff:
            self._events.popleft()
        return {v for _, v in self._events}

    def reset(self) -> None:
        self._events.clear()


class RateDetector:
    """
    Rate-based anomaly detector for NIDS.
    Detects: port scans, brute force, SYN flood, ICMP flood, DNS flood, host sweep, exfiltration.
    """

    def __init__(self, config: Optional[RateDetectorConfig] = None):
        self.config = config or RateDetectorConfig()
        self._init_windows()
        self._last_alert: dict = {}
        logger.info("RateDetector initialized with config thresholds")

    def _init_windows(self):
        """Initialize sliding window trackers"""
        cfg = self.config

        # Port scan: src_ip -> unique dst ports
        self._port_scan: dict = defaultdict(lambda: SetWindow(cfg.port_scan_window_sec))

        # Host sweep: src_ip -> unique dst IPs
        self._host_sweep: dict = defaultdict(
            lambda: SetWindow(cfg.host_sweep_window_sec)
        )

        # SYN flood: src_ip -> SYN count
        self._syn_flood: dict = defaultdict(
            lambda: SlidingWindow(cfg.syn_flood_window_sec)
        )

        # ICMP flood: src_ip -> ICMP count
        self._icmp_flood: dict = defaultdict(
            lambda: SlidingWindow(cfg.icmp_flood_window_sec)
        )

        # DNS flood: src_ip -> DNS query count
        self._dns_flood: dict = defaultdict(
            lambda: SlidingWindow(cfg.dns_flood_window_sec)
        )

        # Brute force: (src_ip, dst_ip, dst_port) -> attempts
        self._brute: dict = defaultdict(
            lambda: SlidingWindow(cfg.brute_force_window_sec)
        )

        # Exfiltration: (src_ip, dst_ip) -> byte count
        self._exfil: dict = defaultdict(lambda: {"ts": None, "bytes": 0})

        # Byte accumulation for exfil
        self._exfil_bytes: dict = defaultdict(int)

    def process(self, packet: PacketEvent) -> List[SignalEvent]:
        """Process a packet and return any generated signals"""
        signals: List[SignalEvent] = []
        now = packet.timestamp

        signals.extend(self._check_port_scan(packet, now))
        signals.extend(self._check_host_sweep(packet, now))
        signals.extend(self._check_syn_flood(packet, now))
        signals.extend(self._check_icmp_flood(packet, now))
        signals.extend(self._check_dns_flood(packet, now))
        signals.extend(self._check_brute_force(packet, now))
        signals.extend(self._check_exfiltration(packet, now))

        for signal in signals:
            logger.warning(f"Rate signal: {signal}")

        return signals

    def _check_port_scan(self, pkt: PacketEvent, now: float) -> List[SignalEvent]:
        cfg = self.config
        self._port_scan[pkt.src_ip].add(now, pkt.dst_port)
        count = self._port_scan[pkt.src_ip].unique_count(now)

        if count >= cfg.port_scan_threshold:
            return self._maybe_alert(
                source="rate",
                rule_id="RATE-001",
                severity=Severity.HIGH,
                src_ip=pkt.src_ip,
                dst_ip=pkt.dst_ip,
                dst_port=None,
                count=count,
                window_sec=cfg.port_scan_window_sec,
                now=now,
                description=f"Port scan: {count} unique ports in {cfg.port_scan_window_sec}s",
            )
        return []

    def _check_host_sweep(self, pkt: PacketEvent, now: float) -> List[SignalEvent]:
        cfg = self.config
        self._host_sweep[pkt.src_ip].add(now, pkt.dst_ip)
        count = self._host_sweep[pkt.src_ip].unique_count(now)

        if count >= cfg.host_sweep_threshold:
            return self._maybe_alert(
                source="rate",
                rule_id="RATE-005",
                severity=Severity.MEDIUM,
                src_ip=pkt.src_ip,
                dst_ip="multiple",
                dst_port=None,
                count=count,
                window_sec=cfg.host_sweep_window_sec,
                now=now,
                description=f"Host sweep: {count} hosts probed in {cfg.host_sweep_window_sec}s",
            )
        return []

    def _check_syn_flood(self, pkt: PacketEvent, now: float) -> List[SignalEvent]:
        if pkt.proto != "TCP" or "S" not in pkt.flags or "A" in pkt.flags:
            return []

        cfg = self.config
        self._syn_flood[pkt.src_ip].add(now)
        count = self._syn_flood[pkt.src_ip].count(now)

        if count >= cfg.syn_flood_threshold:
            return self._maybe_alert(
                source="rate",
                rule_id="RATE-003",
                severity=Severity.CRITICAL,
                src_ip=pkt.src_ip,
                dst_ip=pkt.dst_ip,
                dst_port=pkt.dst_port,
                count=count,
                window_sec=cfg.syn_flood_window_sec,
                now=now,
                description=f"SYN flood: {count} SYN packets in {cfg.syn_flood_window_sec}s",
            )
        return []

    def _check_icmp_flood(self, pkt: PacketEvent, now: float) -> List[SignalEvent]:
        if pkt.proto != "ICMP":
            return []

        cfg = self.config
        self._icmp_flood[pkt.src_ip].add(now)
        count = self._icmp_flood[pkt.src_ip].count(now)

        if count >= cfg.icmp_flood_threshold:
            return self._maybe_alert(
                source="rate",
                rule_id="RATE-004",
                severity=Severity.MEDIUM,
                src_ip=pkt.src_ip,
                dst_ip=pkt.dst_ip,
                dst_port=None,
                count=count,
                window_sec=cfg.icmp_flood_window_sec,
                now=now,
                description=f"ICMP flood: {count} ICMP packets in {cfg.icmp_flood_window_sec}s",
            )
        return []

    def _check_dns_flood(self, pkt: PacketEvent, now: float) -> List[SignalEvent]:
        if pkt.proto != "UDP" or pkt.dst_port != 53:
            return []

        cfg = self.config
        self._dns_flood[pkt.src_ip].add(now)
        count = self._dns_flood[pkt.src_ip].count(now)

        if count >= cfg.dns_flood_threshold:
            return self._maybe_alert(
                source="rate",
                rule_id="RATE-006",
                severity=Severity.MEDIUM,
                src_ip=pkt.src_ip,
                dst_ip=pkt.dst_ip,
                dst_port=53,
                count=count,
                window_sec=cfg.dns_flood_window_sec,
                now=now,
                description=f"DNS flood: {count} DNS queries in {cfg.dns_flood_window_sec}s",
            )
        return []

    def _check_brute_force(self, pkt: PacketEvent, now: float) -> List[SignalEvent]:
        AUTH_PORTS = {21, 22, 23, 25, 110, 143, 445, 1433, 3306, 3389, 5900}
        if pkt.dst_port not in AUTH_PORTS:
            return []

        cfg = self.config
        key = f"{pkt.src_ip}->{pkt.dst_ip}:{pkt.dst_port}"
        self._brute[key].add(now)
        count = self._brute[key].count(now)

        if count >= cfg.brute_force_threshold:
            return self._maybe_alert(
                source="rate",
                rule_id="RATE-002",
                severity=Severity.HIGH,
                src_ip=pkt.src_ip,
                dst_ip=pkt.dst_ip,
                dst_port=pkt.dst_port,
                count=count,
                window_sec=cfg.brute_force_window_sec,
                now=now,
                description=f"Brute force: {count} attempts to {pkt.dst_ip}:{pkt.dst_port} in {cfg.brute_force_window_sec}s",
            )
        return []

    def _check_exfiltration(self, pkt: PacketEvent, now: float) -> List[SignalEvent]:
        # Only count outbound traffic from private IPs
        if not self._is_private(pkt.src_ip):
            return []

        cfg = self.config
        key = (pkt.src_ip, pkt.dst_ip)
        self._exfil_bytes[key] += pkt.size

        total_bytes = self._exfil_bytes[key]
        if total_bytes >= cfg.exfil_threshold_bytes:
            # Reset after alert
            self._exfil_bytes[key] = 0
            return self._maybe_alert(
                source="rate",
                rule_id="RATE-007",
                severity=Severity.HIGH,
                src_ip=pkt.src_ip,
                dst_ip=pkt.dst_ip,
                dst_port=None,
                count=total_bytes,
                window_sec=cfg.exfil_window_sec,
                now=now,
                description=f"Exfiltration: {total_bytes} bytes to {pkt.dst_ip} in {cfg.exfil_window_sec}s",
            )
        return []

    def _maybe_alert(
        self,
        source: str,
        rule_id: str,
        severity: str,
        src_ip: str,
        dst_ip: str,
        dst_port: Optional[int],
        count: int,
        window_sec: int,
        now: float,
        description: str,
    ) -> List[SignalEvent]:
        """Create signal if cooldown has expired"""
        cd_key = (rule_id, src_ip)
        last = self._last_alert.get(cd_key, 0)

        if now - last < self.config.cooldown_sec:
            return []

        self._last_alert[cd_key] = now

        score_map = {"critical": 100, "high": 70, "medium": 40, "low": 10}

        return [
            SignalEvent(
                id=str(uuid.uuid4()),
                timestamp=now,
                source=source,
                rule_id=rule_id,
                severity=severity,
                src_ip=src_ip,
                dst_ip=dst_ip,
                dst_port=dst_port,
                proto="TCP",  # Will be set by packet
                description=description,
                score_contribution=score_map.get(severity, 10),
                metadata={"count": count, "window_sec": window_sec},
            )
        ]

    @staticmethod
    def _is_private(ip: str) -> bool:
        parts = ip.split(".")
        if len(parts) != 4:
            return False
        a, b = int(parts[0]), int(parts[1])
        return a == 10 or (a == 172 and 16 <= b <= 31) or (a == 192 and b == 168)

    def reset_ip(self, ip: str) -> None:
        """Clear all state for an IP (e.g., after whitelisting)"""
        for store in (
            self._port_scan,
            self._host_sweep,
            self._syn_flood,
            self._icmp_flood,
            self._dns_flood,
        ):
            if ip in store:
                store[ip].reset()
                del store[ip]

        # Clear brute force entries for this IP
        keys_to_remove = [k for k in self._brute if k.startswith(f"{ip}->")]
        for k in keys_to_remove:
            del self._brute[k]

        # Clear exfil entries
        keys_to_remove = [k for k in self._exfil_bytes if k[0] == ip]
        for k in keys_to_remove:
            del self._exfil_bytes[k]

        logger.info(f"Reset rate detector state for IP: {ip}")

    def get_stats(self) -> dict:
        """Get detector statistics"""
        return {
            "port_scan_active": len(self._port_scan),
            "host_sweep_active": len(self._host_sweep),
            "syn_flood_active": len(self._syn_flood),
            "icmp_flood_active": len(self._icmp_flood),
            "dns_flood_active": len(self._dns_flood),
            "brute_force_active": len(self._brute),
            "exfil_active": len(self._exfil_bytes),
        }
