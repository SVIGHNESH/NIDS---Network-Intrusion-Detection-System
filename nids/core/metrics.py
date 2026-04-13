"""
nids/core/metrics.py
System metrics collection for degradation controller
"""

import time
import threading
import logging
from typing import Optional
from dataclasses import dataclass

logger = logging.getLogger("nids.metrics")


@dataclass
class SystemMetrics:
    """System resource metrics"""

    cpu_percent: float = 0.0
    memory_percent: float = 0.0
    queue_depth: int = 0
    packets_dropped: int = 0
    packets_processed: int = 0
    packets_per_sec: float = 0.0
    avg_processing_latency_ms: float = 0.0
    timestamp: float = 0.0


class MetricsCollector:
    """
    Collects system metrics for degradation decisions.
    """

    def __init__(self, collection_interval_sec: float = 5.0):
        self.collection_interval = collection_interval_sec
        self._running = False
        self._thread: Optional[threading.Thread] = None

        # Metrics
        self._cpu_history: list = []
        self._memory_history: list = []
        self._max_history = 12  # 1 minute of history

        # Packet rate tracking
        self._packet_history: list[
            tuple[float, int]
        ] = []  # (timestamp, packets_processed)
        self._max_packet_history = 60  # 5 minutes of history at 5s intervals

        # External references
        self._capture = None
        self._pipeline = None

    def start(self):
        """Start metrics collection"""
        if self._running:
            return

        self._running = True
        self._thread = threading.Thread(target=self._collect_loop, daemon=True)
        self._thread.start()
        logger.info("Metrics collector started")

    def stop(self):
        """Stop metrics collection"""
        self._running = False
        if self._thread:
            self._thread.join(timeout=5)
        logger.info("Metrics collector stopped")

    def set_references(self, capture=None, pipeline=None):
        """Set references to other components for metrics collection"""
        self._capture = capture
        self._pipeline = pipeline

    def _collect_loop(self):
        """Main collection loop"""
        while self._running:
            try:
                metrics = self._collect()
                self._update_history(metrics)
                time.sleep(self.collection_interval)
            except Exception as e:
                logger.error(f"Metrics collection error: {e}")

    def _collect(self) -> SystemMetrics:
        """Collect current metrics"""
        metrics = SystemMetrics(timestamp=time.time())

        # Get capture stats if available
        if self._capture:
            try:
                capture_stats = self._capture.get_stats()
                metrics.queue_depth = capture_stats.queue_size
                metrics.packets_dropped = capture_stats.packets_dropped
                metrics.packets_processed = capture_stats.packets_processed
            except Exception:
                pass

        # Get CPU/memory using psutil if available
        try:
            import psutil

            metrics.cpu_percent = psutil.cpu_percent(interval=0.1)
            metrics.memory_percent = psutil.virtual_memory().percent
        except ImportError:
            # Fallback: use simple estimation
            # On Linux, read /proc/stat for CPU
            metrics.cpu_percent = self._estimate_cpu()
            metrics.memory_percent = self._estimate_memory()

        return metrics

    def _estimate_cpu(self) -> float:
        """Estimate CPU usage without psutil"""
        try:
            with open("/proc/stat", "r") as f:
                line = f.readline()
                parts = line.split()
                if len(parts) >= 5 and parts[0] == "cpu":
                    # Simple estimation - just use idle as proxy
                    # In production, use proper delta calculation
                    return 0.0
        except Exception:
            pass
        return 0.0

    def _estimate_memory(self) -> float:
        """Estimate memory usage without psutil"""
        try:
            with open("/proc/meminfo", "r") as f:
                total = 0
                available = 0
                for line in f:
                    if line.startswith("MemTotal:"):
                        total = int(line.split()[1])
                    elif line.startswith("MemAvailable:"):
                        available = int(line.split()[1])
                if total > 0:
                    return ((total - available) / total) * 100
        except Exception:
            pass
        return 0.0

    def _update_history(self, metrics: SystemMetrics):
        """Update metrics history"""
        self._cpu_history.append(metrics.cpu_percent)
        self._memory_history.append(metrics.memory_percent)

        # Track packet counts for rate calculation
        self._packet_history.append((metrics.timestamp, metrics.packets_processed))

        if len(self._cpu_history) > self._max_history:
            self._cpu_history.pop(0)
        if len(self._memory_history) > self._max_history:
            self._memory_history.pop(0)
        if len(self._packet_history) > self._max_packet_history:
            self._packet_history.pop(0)

    def get_current_metrics(self) -> SystemMetrics:
        """Get current system metrics"""
        return self._collect()

    def get_avg_metrics(self) -> SystemMetrics:
        """Get average metrics over collection period"""
        metrics = SystemMetrics(timestamp=time.time())

        if self._cpu_history:
            metrics.cpu_percent = sum(self._cpu_history) / len(self._cpu_history)
        if self._memory_history:
            metrics.memory_percent = sum(self._memory_history) / len(
                self._memory_history
            )

        # Calculate packets per second from packet history
        if len(self._packet_history) >= 2:
            oldest = self._packet_history[0]
            newest = self._packet_history[-1]
            time_diff = newest[0] - oldest[0]
            pkts_diff = newest[1] - oldest[1]
            if time_diff > 0:
                metrics.packets_per_sec = pkts_diff / time_diff

        # Get current queue/drop stats
        if self._capture:
            try:
                stats = self._capture.get_stats()
                metrics.queue_depth = stats.queue_size
                metrics.packets_dropped = stats.packets_dropped
                metrics.packets_processed = stats.packets_processed
            except Exception:
                pass

        return metrics


def create_metrics_collector(interval: float = 5.0) -> MetricsCollector:
    """Factory function to create metrics collector"""
    return MetricsCollector(collection_interval_sec=interval)
