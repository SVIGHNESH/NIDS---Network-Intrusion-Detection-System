"""
nids/core/capture.py
Packet capture with bounded queue - metadata-first approach
"""

import time
import logging
import threading
import queue
from typing import Optional, Callable
from dataclasses import dataclass

logger = logging.getLogger("nids.capture")


@dataclass
class CaptureStats:
    """Capture statistics"""

    packets_processed: int = 0
    packets_dropped: int = 0
    queue_size: int = 0
    last_timestamp: float = 0


class PacketCapture:
    """
    Metadata-first packet capture with bounded queue.
    Designed for low-spec stability.
    """

    def __init__(
        self,
        interface: str = "auto",
        bpf_filter: str = "ip and (tcp or udp or icmp)",
        queue_maxsize: int = 1000,
        buffer_size: int = 65535,
    ):
        # Auto-detect interface if needed
        if interface == "auto" or not interface:
            from nids.core.config import get_default_interface

            interface = get_default_interface()

        self.interface = interface
        self.bpf_filter = bpf_filter
        self.queue_maxsize = queue_maxsize
        self.buffer_size = buffer_size
        self._packet_queue: queue.Queue = queue.Queue(maxsize=queue_maxsize)
        self._running = False
        self._stats = CaptureStats()
        self._stats_lock = threading.Lock()
        self._callback: Optional[Callable] = None
        self._capture_thread: Optional[threading.Thread] = None

    def set_callback(self, callback: Callable):
        """Set packet processing callback"""
        self._callback = callback

    def start(self):
        """Start packet capture"""
        if self._running:
            logger.warning("Capture already running")
            return

        self._running = True
        self._capture_thread = threading.Thread(target=self._capture_loop, daemon=True)
        self._capture_thread.start()
        logger.info(
            f"Capture started on {self.interface} with filter '{self.bpf_filter}'"
        )

    def stop(self):
        """Stop packet capture"""
        self._running = False
        if self._capture_thread:
            self._capture_thread.join(timeout=5)
        logger.info("Capture stopped")

    def _capture_loop(self):
        """Main capture loop - to be implemented with scapy or similar"""
        # This is a placeholder - actual implementation will use scapy
        # For now, we'll support replay mode via process_packets()
        logger.info(
            "Capture loop started (placeholder - use process_packets for replay)"
        )

    def process_packets(self, packets: list):
        """
        Process a batch of packets (for replay/testing).
        Adds packets to queue and processes them.
        """
        for pkt in packets:
            self._enqueue_packet(pkt)

    def _enqueue_packet(self, packet):
        """Add packet to processing queue"""
        try:
            self._packet_queue.put(packet, block=False)
        except queue.Full:
            with self._stats_lock:
                self._stats.packets_dropped += 1
            logger.warning("Packet queue full, dropping packet")

    def _process_queue(self):
        """Process packets from queue"""
        while self._running:
            try:
                packet = self._packet_queue.get(timeout=0.1)
                with self._stats_lock:
                    self._stats.packets_processed += 1
                    self._stats.last_timestamp = time.time()

                if self._callback:
                    try:
                        self._callback(packet)
                    except Exception as e:
                        logger.error(f"Callback error: {e}")

                self._stats.queue_size = self._packet_queue.qsize()
            except queue.Empty:
                continue
            except Exception as e:
                logger.error(f"Queue processing error: {e}")

    def get_stats(self) -> CaptureStats:
        """Get capture statistics"""
        with self._stats_lock:
            self._stats.queue_size = self._packet_queue.qsize()
            return CaptureStats(
                packets_processed=self._stats.packets_processed,
                packets_dropped=self._stats.packets_dropped,
                queue_size=self._stats.queue_size,
                last_timestamp=self._stats.last_timestamp,
            )

    def is_running(self) -> bool:
        """Check if capture is running"""
        return self._running


class ScapyCapture(PacketCapture):
    """
    Scapy-based packet capture.
    Requires: pip install scapy
    """

    def _capture_loop(self):
        """Scapy capture implementation"""
        try:
            from scapy.all import sniff, IP, TCP, UDP, ICMP
        except ImportError:
            logger.error("Scapy not installed. Install with: pip install scapy")
            return

        def packet_handler(pkt):
            if IP not in pkt:
                return

            from nids.core.schemas import PacketEvent

            ip = pkt[IP]
            proto = (
                "TCP"
                if TCP in pkt
                else "UDP"
                if UDP in pkt
                else "ICMP"
                if ICMP in pkt
                else "OTHER"
            )

            sport, dport = 0, 0
            flags = ""
            if TCP in pkt:
                sport = pkt[TCP].sport
                dport = pkt[TCP].dport
                flag_map = {
                    0x01: "F",
                    0x02: "S",
                    0x04: "R",
                    0x08: "P",
                    0x10: "A",
                    0x20: "U",
                }
                flags = "".join(v for k, v in flag_map.items() if pkt[TCP].flags & k)
            elif UDP in pkt:
                sport = pkt[UDP].sport
                dport = pkt[UDP].dport

            packet = PacketEvent(
                timestamp=time.time(),
                src_ip=ip.src,
                dst_ip=ip.dst,
                src_port=sport,
                dst_port=dport,
                proto=proto,
                flags=flags,
                size=len(pkt),
                payload_preview=bytes(ip.payload)[:256],
            )

            self._enqueue_packet(packet)

        # Start processing queue in background
        processor = threading.Thread(target=self._process_queue, daemon=True)
        processor.start()

        # Start scapy sniff
        try:
            sniff(
                iface=self.interface,
                prn=packet_handler,
                store=False,
                filter=self.bpf_filter,
            )
        except Exception as e:
            logger.error(f"Capture error: {e}")
            self._running = False
