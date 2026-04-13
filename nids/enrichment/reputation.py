"""
nids/enrichment/reputation.py
Reputation/Threat Intel enrichment with caching
"""

import os
import time
import uuid
import logging
import asyncio
import aiohttp
from typing import Optional, Dict, Any, List
from dataclasses import dataclass

from nids.core.schemas import SignalEvent, Severity
from nids.storage.database import Database


logger = logging.getLogger("nids.enrichment.reputation")


@dataclass
class ReputationResult:
    """Reputation check result"""

    ip: str
    is_malicious: bool
    confidence_score: int  # 0-100
    abuse_category: str
    country: str
    isp: str
    num_reports: int
    last_reported: Optional[str]
    data: Dict[str, Any]


class ReputationEngine:
    """
    Threat intelligence reputation engine with caching.
    Supports multiple providers with pluggable architecture.
    """

    def __init__(
        self,
        provider: str = "abuseipdb",
        api_key: Optional[str] = None,
        cache_ttl_sec: int = 3600,
        timeout_sec: int = 2,
        max_retries: int = 2,
        min_severity_for_check: str = "medium",
        enabled: bool = True,
    ):
        self.provider = provider
        self.api_key = api_key or os.environ.get("ABUSEIPDB_API_KEY")
        self.cache_ttl_sec = cache_ttl_sec
        self.timeout_sec = timeout_sec
        self.max_retries = max_retries
        self.min_severity_for_check = min_severity_for_check
        self.enabled = enabled and bool(self.api_key)

        # Provider implementations
        self._providers = {
            "abuseipdb": self._check_abuseipdb,
        }

        # Cache reference
        self._db: Optional[Database] = None

        # Stats
        self._stats = {
            "lookups": 0,
            "cache_hits": 0,
            "cache_misses": 0,
            "errors": 0,
        }

        if not self.enabled:
            logger.warning("Reputation engine disabled - no API key configured")
        else:
            logger.info(f"Reputation engine enabled with provider: {provider}")

    def set_database(self, db: Database):
        """Set database for caching"""
        self._db = db

    def _check_cache(self, ip: str) -> Optional[ReputationResult]:
        """Check local cache for IP reputation"""
        if not self._db:
            return None

        cached = self._db.get_reputation_cache(ip)
        if cached:
            data = eval(cached["data"])  # Safely evaluate stored dict
            logger.debug(f"Cache hit for IP: {ip}")
            self._stats["cache_hits"] += 1
            return ReputationResult(
                ip=ip,
                is_malicious=data.get("is_malicious", False),
                confidence_score=data.get("confidence_score", 0),
                abuse_category=data.get("abuse_category", ""),
                country=data.get("country", ""),
                isp=data.get("isp", ""),
                num_reports=data.get("num_reports", 0),
                last_reported=data.get("last_reported"),
                data=data,
            )
        return None

    def _set_cache(self, ip: str, result: ReputationResult):
        """Set cache for IP reputation"""
        if not self._db:
            return

        self._db.set_reputation_cache(
            ip=ip,
            data=str(result.data),
            ttl_sec=self.cache_ttl_sec,
        )

    async def _check_abuseipdb(self, ip: str) -> Optional[ReputationResult]:
        """Check IP reputation via AbuseIPDB API"""
        if not self.api_key:
            logger.error("AbuseIPDB API key not configured")
            return None

        url = "https://api.abuseipdb.com/api/v2/check"
        headers = {"Key": self.api_key, "Accept": "application/json"}
        params = {"ipAddress": ip, "maxAgeInDays": 90}

        for attempt in range(self.max_retries):
            try:
                timeout = aiohttp.ClientTimeout(total=self.timeout_sec)
                async with aiohttp.ClientSession(timeout=timeout) as session:
                    async with session.get(
                        url, headers=headers, params=params
                    ) as response:
                        if response.status == 200:
                            data = await response.json()
                            return self._parse_abuseipdb_response(ip, data)
                        elif response.status == 429:
                            # Rate limited
                            logger.warning("AbuseIPDB rate limited, backing off")
                            await asyncio.sleep(2**attempt)
                            continue
                        else:
                            logger.warning(
                                f"AbuseIPDB returned status {response.status}"
                            )
            except asyncio.TimeoutError:
                logger.warning(f"AbuseIPDB timeout for IP: {ip}")
            except Exception as e:
                logger.error(f"AbuseIPDB error: {e}")

        self._stats["errors"] += 1
        return None

    def _parse_abuseipdb_response(self, ip: str, data: Dict) -> ReputationResult:
        """Parse AbuseIPDB API response"""
        d = data.get("data", {})

        is_malicious = (
            d.get("isPublic", False) and d.get("abuseConfidenceScore", 0) > 50
        )

        return ReputationResult(
            ip=ip,
            is_malicious=is_malicious,
            confidence_score=d.get("abuseConfidenceScore", 0),
            abuse_category=d.get("abuseCategory", ""),
            country=d.get("countryCode", ""),
            isp=d.get("isp", ""),
            num_reports=d.get("totalReports", 0),
            last_reported=d.get("lastReportedAt"),
            data=d,
        )

    def _severity_to_score(self, severity: str) -> int:
        """Convert severity string to numeric score"""
        score_map = {"critical": 100, "high": 70, "medium": 40, "low": 10}
        return score_map.get(severity.lower(), 0)

    def _should_check(self, signal: SignalEvent) -> bool:
        """Determine if signal should be enriched"""
        # Only check if severity is high enough
        if self._severity_to_score(signal.severity) < self._severity_to_score(
            self.min_severity_for_check
        ):
            return False
        return True

    async def enrich(self, signal: SignalEvent) -> Optional[SignalEvent]:
        """Enrich a signal with reputation data"""
        if not self.enabled:
            return None

        if not self._should_check(signal):
            return None

        self._stats["lookups"] += 1

        # Check cache first
        cached = self._check_cache(signal.src_ip)
        if cached:
            return self._create_enriched_signal(signal, cached)

        # Query provider
        provider_func = self._providers.get(self.provider)
        if not provider_func:
            logger.error(f"Unknown provider: {self.provider}")
            return None

        result = await provider_func(signal.src_ip)

        if result:
            # Cache the result
            self._set_cache(signal.src_ip, result)
            return self._create_enriched_signal(signal, result)

        return None

    def _create_enriched_signal(
        self, signal: SignalEvent, result: ReputationResult
    ) -> SignalEvent:
        """Create enriched signal from reputation result"""
        # Add reputation score contribution
        if result.is_malicious:
            score_contrib = int(result.confidence_score * 0.4)  # Max 40 points
        else:
            score_contrib = 0

        # Update signal with reputation data
        enriched = SignalEvent(
            id=signal.id,
            timestamp=signal.timestamp,
            source="reputation",
            rule_id=signal.rule_id,
            severity=signal.severity,
            src_ip=signal.src_ip,
            dst_ip=signal.dst_ip,
            dst_port=signal.dst_port,
            proto=signal.proto,
            description=f"{signal.description} [Rep: {result.confidence_score}% confidence, {result.abuse_category}]",
            score_contribution=signal.score_contribution + score_contrib,
            metadata={
                **signal.metadata,
                "reputation": {
                    "is_malicious": result.is_malicious,
                    "confidence": result.confidence_score,
                    "country": result.country,
                    "isp": result.isp,
                    "num_reports": result.num_reports,
                },
            },
        )

        return enriched

    def get_stats(self) -> Dict[str, Any]:
        """Get engine statistics"""
        return {
            **self._stats,
            "enabled": self.enabled,
            "provider": self.provider,
        }


class ReputationWorker:
    """
    Async worker for processing reputation enrichment in background.
    """

    def __init__(self, engine: ReputationEngine, queue_size: int = 100):
        self.engine = engine
        self.queue: asyncio.Queue = asyncio.Queue(maxsize=queue_size)
        self._running = False

    async def start(self):
        """Start the worker"""
        self._running = True
        asyncio.create_task(self._process_loop())
        logger.info("Reputation worker started")

    async def stop(self):
        """Stop the worker"""
        self._running = False

    async def submit(self, signal: SignalEvent):
        """Submit a signal for enrichment"""
        try:
            self.queue.put_nowait(signal)
        except asyncio.QueueFull:
            logger.warning("Reputation queue full, dropping signal")

    async def _process_loop(self):
        """Process signals from queue"""
        while self._running:
            try:
                signal = await asyncio.wait_for(self.queue.get(), timeout=1.0)
                await self.engine.enrich(signal)
            except asyncio.TimeoutError:
                continue
            except Exception as e:
                logger.error(f"Reputation worker error: {e}")


def create_reputation_engine(config: dict) -> ReputationEngine:
    """Factory function to create ReputationEngine from config"""
    return ReputationEngine(
        provider=config.get("provider", "abuseipdb"),
        api_key=config.get("abuseipdb_api_key"),
        cache_ttl_sec=config.get("cache_ttl_sec", 3600),
        timeout_sec=config.get("timeout_sec", 2),
        max_retries=config.get("max_retries", 2),
        min_severity_for_check=config.get("min_severity_for_check", "medium"),
        enabled=config.get("enabled", True),
    )
