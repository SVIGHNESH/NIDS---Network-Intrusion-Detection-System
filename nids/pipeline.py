"""
nids/pipeline.py
Main NIDS pipeline that ties capture, detection, enrichment, correlation, and degradation together
"""

import time
import logging
import threading
import asyncio
from typing import Optional, Callable, List
from dataclasses import dataclass

from nids.core.schemas import PacketEvent, SignalEvent, AlertEvent
from nids.core.config import get_settings, Settings
from nids.core.capture import PacketCapture, ScapyCapture
from nids.core.correlation import AlertCorrelator
from nids.core.degradation import DegradationController, RuntimeProfile, Feature
from nids.core.metrics import MetricsCollector, SystemMetrics
from nids.detectors.rate_engine import RateDetector
from nids.detectors.yara_engine import YaraDetector
from nids.enrichment.reputation import ReputationEngine, ReputationWorker
from nids.storage.database import Database, get_database


logger = logging.getLogger("nids.pipeline")


@dataclass
class PipelineStats:
    """Pipeline statistics"""

    packets_processed: int = 0
    signals_generated: int = 0
    alerts_generated: int = 0
    reputation_enrichments: int = 0
    queue_depth: int = 0
    yara_enabled: bool = True
    reputation_enabled: bool = True


class NIDSPipeline:
    """
    Main NIDS pipeline that orchestrates all components.
    Includes degradation controller for low-spec stability.
    """

    def __init__(self, settings: Optional[Settings] = None):
        self.settings = settings or get_settings()

        # Initialize components
        self._init_components()

        # State
        self._running = False
        self._stats = PipelineStats()
        self._stats_lock = threading.Lock()

        # Callbacks
        self._alert_callback: Optional[Callable[[AlertEvent], None]] = None

    def _init_components(self):
        """Initialize all pipeline components"""
        # Database
        self.db = get_database(
            self.settings.database.path, self.settings.database.retention_days
        )
        logger.info("Database initialized")

        # Capture
        self.capture = ScapyCapture(
            interface=self.settings.capture.interface,
            bpf_filter=self.settings.capture.bpf_filter,
            queue_maxsize=self.settings.capture.queue_maxsize,
        )
        self.capture.set_callback(self._process_packet)
        logger.info("Capture initialized")

        # Rate detector (always enabled)
        self.rate_detector = RateDetector(self.settings.rate_detector)
        logger.info("Rate detector initialized")

        # Degradation controller
        profile = (
            RuntimeProfile.LITE
            if self.settings.runtime.profile == "lite"
            else RuntimeProfile.ENHANCED
        )
        self.degradation = DegradationController(profile=profile)
        logger.info(f"Degradation controller initialized with profile: {profile.value}")

        # Metrics collector
        self.metrics = MetricsCollector(collection_interval_sec=5.0)
        self.metrics.set_references(capture=self.capture, pipeline=self)
        logger.info("Metrics collector initialized")

        # YARA detector (controlled by degradation)
        if self.settings.runtime.enable_yara:
            self.yara_detector = YaraDetector(
                rules_file=self.settings.yara.rules_file,
                enabled=self.settings.yara.enabled,
                timeout_ms=self.settings.yara.timeout_ms,
                max_payload_size=self.settings.yara.max_payload_size,
                gating_enabled=self.settings.yara.gating_enabled,
                gating_ports=self.settings.yara.gating_ports,
            )
            self.yara_detector.initialize()
        else:
            self.yara_detector = None
            logger.info("YARA detector disabled by runtime config")

        # Reputation engine (controlled by degradation)
        if self.settings.runtime.enable_reputation:
            self.reputation_engine = ReputationEngine(
                provider=self.settings.reputation.provider,
                api_key=self.settings.reputation.abuseipdb_api_key,
                cache_ttl_sec=self.settings.reputation.cache_ttl_sec,
                timeout_sec=self.settings.reputation.timeout_sec,
                max_retries=self.settings.reputation.max_retries,
                min_severity_for_check=self.settings.reputation.min_severity_for_check,
                enabled=self.settings.reputation.enabled,
            )
            self.reputation_engine.set_database(self.db)
            self.reputation_worker = ReputationWorker(self.reputation_engine)
            self._reputation_loop_running = False
        else:
            self.reputation_engine = None
            self.reputation_worker = None
            logger.info("Reputation engine disabled by runtime config")

        # Correlator
        self.correlator = AlertCorrelator(self.settings.correlator)
        logger.info("Correlator initialized")

    def _process_packet(self, packet: PacketEvent):
        """Process a packet through the detection pipeline"""
        try:
            with self._stats_lock:
                self._stats.packets_processed += 1

            # Run detectors
            signals: List[SignalEvent] = []

            # Rate detection (always on)
            rate_signals = self.rate_detector.process(packet)
            signals.extend(rate_signals)

            # YARA detection (check degradation state)
            if self.yara_detector and self.yara_detector.is_initialized():
                if self.degradation.is_enabled(Feature.YARA_DETECTION):
                    yara_signals = self.yara_detector.process(packet)
                    signals.extend(yara_signals)
                    with self._stats_lock:
                        self._stats.yara_enabled = True
                else:
                    with self._stats_lock:
                        self._stats.yara_enabled = False

            # Process signals
            if signals:
                self._process_signals(signals)

        except Exception as e:
            logger.error(f"Error processing packet: {e}")

    def _process_signals(self, signals: List[SignalEvent]):
        """Process signals through correlation and enrichment"""
        try:
            # Store signals in database
            for signal in signals:
                self.db.insert_signal(signal)

            with self._stats_lock:
                self._stats.signals_generated += len(signals)

            # Correlate signals into alerts
            alerts = self.correlator.process_signals(signals)

            # Store and broadcast alerts
            for alert in alerts:
                self._handle_alert(alert)

        except Exception as e:
            logger.error(f"Error processing signals: {e}")

    def _handle_alert(self, alert: AlertEvent):
        """Handle a generated alert"""
        try:
            # Store in database
            self.db.insert_alert(alert)

            with self._stats_lock:
                self._stats.alerts_generated += 1

            # Broadcast via WebSocket (thread-safe)
            from nids.api.server import ws_manager
            import threading

            def broadcast_alert():
                try:
                    # Create new event loop for this thread
                    loop = asyncio.new_event_loop()
                    asyncio.set_event_loop(loop)
                    try:
                        loop.run_until_complete(ws_manager.broadcast(alert.to_dict()))
                    finally:
                        loop.close()
                except Exception as ws_err:
                    logger.warning(f"WebSocket broadcast: {ws_err}")

            # Run broadcast in a separate thread to not block
            broadcast_thread = threading.Thread(target=broadcast_alert, daemon=True)
            broadcast_thread.start()

            # Call custom callback if set
            if self._alert_callback:
                self._alert_callback(alert)

            logger.warning(f"Alert generated: {alert.title} ({alert.severity})")

        except Exception as e:
            logger.error(f"Error handling alert: {e}")

    def _update_degradation(self):
        """Update degradation state based on metrics"""
        try:
            metrics = self.metrics.get_avg_metrics()
            self.degradation.update_metrics(metrics)

            # Update stats with current state
            state = self.degradation.get_state()
            with self._stats_lock:
                self._stats.yara_enabled = state.yara_detection
                self._stats.reputation_enabled = state.reputation_enrichment

        except Exception as e:
            logger.error(f"Error updating degradation: {e}")

    def start(self):
        """Start the NIDS pipeline"""
        if self._running:
            logger.warning("Pipeline already running")
            return

        self._running = True

        # Start metrics collector
        self.metrics.start()

        # Start capture
        self.capture.start()

        # Start reputation worker if enabled (run in background thread)
        if self.reputation_worker and not self._reputation_loop_running:
            self._reputation_loop_running = True
            rep_thread = threading.Thread(
                target=self._run_reputation_worker, daemon=True
            )
            rep_thread.start()

        logger.info("NIDS pipeline started")

    def _run_reputation_worker(self):
        """Run reputation worker in a new event loop"""
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            loop.run_until_complete(self.reputation_worker.start())
            loop.run_forever()
        except Exception as e:
            logger.error(f"Reputation worker error: {e}")
        finally:
            loop.close()

    def stop(self):
        """Stop the NIDS pipeline"""
        self._running = False

        # Stop metrics collector
        self.metrics.stop()

        # Stop capture
        self.capture.stop()

        # Stop reputation worker
        if self.reputation_worker and self._reputation_loop_running:
            try:
                loop = asyncio.get_event_loop()
                loop.call_soon_threadsafe(
                    lambda: asyncio.create_task(self.reputation_worker.stop())
                )
            except Exception:
                pass
            self._reputation_loop_running = False

        logger.info("NIDS pipeline stopped")

    def set_alert_callback(self, callback: Callable[[AlertEvent], None]):
        """Set callback for alert handling"""
        self._alert_callback = callback

    def get_stats(self) -> PipelineStats:
        """Get pipeline statistics"""
        with self._stats_lock:
            capture_stats = self.capture.get_stats()
            self._stats.queue_depth = capture_stats.queue_size
            return PipelineStats(
                packets_processed=self._stats.packets_processed,
                signals_generated=self._stats.signals_generated,
                alerts_generated=self._stats.alerts_generated,
                reputation_enrichments=self._stats.reputation_enrichments,
                queue_depth=self._stats.queue_depth,
                yara_enabled=self._stats.yara_enabled,
                reputation_enabled=self._stats.reputation_enabled,
            )

    def is_running(self) -> bool:
        """Check if pipeline is running"""
        return self._running

    def reset_detection_state(self, ip: str):
        """Reset detection state for a specific IP"""
        self.rate_detector.reset_ip(ip)
        logger.info(f"Detection state reset for IP: {ip}")

    def get_degradation_state(self):
        """Get current degradation state"""
        return self.degradation.get_state()

    def get_metrics(self) -> SystemMetrics:
        """Get current system metrics"""
        return self.metrics.get_avg_metrics()


# Global pipeline instance
_pipeline: Optional[NIDSPipeline] = None


def get_pipeline() -> NIDSPipeline:
    """Get or create global pipeline instance"""
    global _pipeline
    if _pipeline is None:
        _pipeline = NIDSPipeline()
    return _pipeline


def start_nids():
    """Start the NIDS pipeline"""
    pipeline = get_pipeline()
    pipeline.start()


def stop_nids():
    """Stop the NIDS pipeline"""
    global _pipeline
    if _pipeline:
        _pipeline.stop()
        _pipeline = None
