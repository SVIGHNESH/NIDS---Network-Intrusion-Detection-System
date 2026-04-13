"""
nids/storage/database.py
SQLite database layer for alerts, signals, and reputation cache
"""

import sqlite3
import logging
import time
import threading
from pathlib import Path
from typing import Optional, List, Dict, Any
from contextlib import contextmanager

from nids.core.schemas import SignalEvent, AlertEvent


logger = logging.getLogger("nids.storage")


class Database:
    """SQLite database manager for NIDS"""

    def __init__(self, db_path: str, retention_days: int = 14):
        self.db_path = db_path
        self.retention_days = retention_days
        self._conn: Optional[sqlite3.Connection] = None
        self._lock = threading.Lock()
        self._init_database()

    def _init_database(self):
        """Initialize database schema"""
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)

        with self._get_connection() as conn:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA busy_timeout=5000")

            # Signals table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS signals (
                    id TEXT PRIMARY KEY,
                    timestamp REAL NOT NULL,
                    source TEXT NOT NULL,
                    rule_id TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    src_ip TEXT NOT NULL,
                    dst_ip TEXT NOT NULL,
                    dst_port INTEGER,
                    proto TEXT NOT NULL,
                    description TEXT,
                    raw_match TEXT,
                    score_contribution INTEGER DEFAULT 0,
                    metadata TEXT,
                    created_at REAL DEFAULT (strftime('%s', 'now'))
                )
            """)

            # Alerts table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS alerts (
                    id TEXT PRIMARY KEY,
                    timestamp REAL NOT NULL,
                    severity TEXT NOT NULL,
                    title TEXT NOT NULL,
                    description TEXT,
                    src_ip TEXT NOT NULL,
                    dst_ip TEXT NOT NULL,
                    dst_port INTEGER,
                    proto TEXT NOT NULL,
                    rule_ids TEXT,
                    signal_count INTEGER DEFAULT 0,
                    score INTEGER DEFAULT 0,
                    raw_signals TEXT,
                    metadata TEXT,
                    created_at REAL DEFAULT (strftime('%s', 'now'))
                )
            """)

            # Reputation cache table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS reputation_cache (
                    ip TEXT PRIMARY KEY,
                    data TEXT NOT NULL,
                    checked_at REAL NOT NULL,
                    expires_at REAL NOT NULL
                )
            """)

            # Create indexes
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_signals_timestamp ON signals(timestamp)"
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_signals_src_ip ON signals(src_ip)"
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_signals_rule_id ON signals(rule_id)"
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts(timestamp)"
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity)"
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_alerts_src_ip ON alerts(src_ip)"
            )

            conn.commit()
            logger.info(f"Database initialized at {self.db_path}")

    @contextmanager
    def _get_connection(self):
        """Get database connection with context manager"""
        conn = sqlite3.connect(self.db_path, timeout=10.0)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
        finally:
            conn.close()

    def insert_signal(self, signal: SignalEvent) -> bool:
        """Insert a signal event"""
        try:
            with self._lock:
                with self._get_connection() as conn:
                    conn.execute(
                        """INSERT INTO signals 
                           (id, timestamp, source, rule_id, severity, src_ip, dst_ip, 
                            dst_port, proto, description, raw_match, score_contribution, metadata)
                           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                        (
                            signal.id,
                            signal.timestamp,
                            signal.source,
                            signal.rule_id,
                            signal.severity,
                            signal.src_ip,
                            signal.dst_ip,
                            signal.dst_port,
                            signal.proto,
                            signal.description,
                            signal.raw_match,
                            signal.score_contribution,
                            str(signal.metadata),
                        ),
                    )
                    conn.commit()
            return True
        except Exception as e:
            logger.error(f"Failed to insert signal: {e}")
            return False

    def insert_alert(self, alert: AlertEvent) -> bool:
        """Insert an alert event"""
        try:
            with self._lock:
                with self._get_connection() as conn:
                    conn.execute(
                        """INSERT INTO alerts 
                           (id, timestamp, severity, title, description, src_ip, dst_ip,
                            dst_port, proto, rule_ids, signal_count, score, raw_signals, metadata)
                           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                        (
                            alert.id,
                            alert.timestamp,
                            alert.severity,
                            alert.title,
                            alert.description,
                            alert.src_ip,
                            alert.dst_ip,
                            alert.dst_port,
                            alert.proto,
                            ",".join(alert.rule_ids),
                            alert.signal_count,
                            alert.score,
                            str(alert.raw_signals),
                            str(alert.metadata),
                        ),
                    )
                    conn.commit()
            return True
        except Exception as e:
            logger.error(f"Failed to insert alert: {e}")
            return False

    def get_alerts(
        self,
        limit: int = 100,
        offset: int = 0,
        severity: Optional[str] = None,
        src_ip: Optional[str] = None,
        rule_id: Optional[str] = None,
        since: Optional[float] = None,
    ) -> List[Dict[str, Any]]:
        """Query alerts with filters"""
        query = "SELECT * FROM alerts WHERE 1=1"
        params = []

        if severity:
            query += " AND severity = ?"
            params.append(severity)
        if src_ip:
            query += " AND src_ip = ?"
            params.append(src_ip)
        if rule_id:
            query += " AND rule_ids LIKE ?"
            params.append(f"%{rule_id}%")
        if since:
            query += " AND timestamp >= ?"
            params.append(since)

        query += " ORDER BY timestamp DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])

        with self._get_connection() as conn:
            cursor = conn.execute(query, params)
            return [dict(row) for row in cursor.fetchall()]

    def get_alert_counts_by_severity(self) -> Dict[str, int]:
        """Get alert counts grouped by severity"""
        with self._get_connection() as conn:
            cursor = conn.execute(
                "SELECT severity, COUNT(*) as count FROM alerts GROUP BY severity"
            )
            return {row["severity"]: row["count"] for row in cursor.fetchall()}

    def get_top_attacking_ips(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Get top attacking IPs by alert count"""
        with self._get_connection() as conn:
            cursor = conn.execute(
                """SELECT src_ip, COUNT(*) as count 
                   FROM alerts 
                   GROUP BY src_ip 
                   ORDER BY count DESC 
                   LIMIT ?""",
                (limit,),
            )
            return [
                {"ip": row["src_ip"], "count": row["count"]}
                for row in cursor.fetchall()
            ]

    def get_rule_hit_counts(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Get rule hit frequency counts"""
        with self._get_connection() as conn:
            cursor = conn.execute(
                """SELECT rule_ids, COUNT(*) as count 
                   FROM alerts 
                   GROUP BY rule_ids 
                   ORDER BY count DESC 
                   LIMIT ?""",
                (limit,),
            )
            results = []
            for row in cursor.fetchall():
                for rule_id in row["rule_ids"].split(","):
                    results.append({"rule_id": rule_id.strip(), "count": row["count"]})

            # Aggregate by rule_id
            rule_counts = {}
            for r in results:
                rid = r["rule_id"]
                rule_counts[rid] = rule_counts.get(rid, 0) + r["count"]

            return [
                {"rule_id": k, "count": v}
                for k, v in sorted(rule_counts.items(), key=lambda x: -x[1])[:limit]
            ]

    def set_reputation_cache(self, ip: str, data: str, ttl_sec: int = 3600) -> bool:
        """Set reputation data for an IP in cache"""
        try:
            now = time.time()
            with self._lock:
                with self._get_connection() as conn:
                    conn.execute(
                        """INSERT OR REPLACE INTO reputation_cache 
                           (ip, data, checked_at, expires_at) VALUES (?, ?, ?, ?)""",
                        (ip, data, now, now + ttl_sec),
                    )
                    conn.commit()
            return True
        except Exception as e:
            logger.error(f"Failed to set reputation cache: {e}")
            return False

    def get_reputation_cache(self, ip: str) -> Optional[Dict[str, Any]]:
        """Get cached reputation data for an IP"""
        with self._get_connection() as conn:
            cursor = conn.execute(
                "SELECT * FROM reputation_cache WHERE ip = ? AND expires_at > ?",
                (ip, time.time()),
            )
            row = cursor.fetchone()
            if row:
                return {"data": row["data"], "checked_at": row["checked_at"]}
        return None

    def cleanup_old_data(self) -> int:
        """Remove data older than retention period"""
        try:
            cutoff = time.time() - (self.retention_days * 86400)
            with self._lock:
                with self._get_connection() as conn:
                    cursor = conn.execute(
                        "DELETE FROM signals WHERE timestamp < ?", (cutoff,)
                    )
                    signals_deleted = cursor.rowcount
                    cursor = conn.execute(
                        "DELETE FROM alerts WHERE timestamp < ?", (cutoff,)
                    )
                    alerts_deleted = cursor.rowcount
                    conn.execute(
                        "DELETE FROM reputation_cache WHERE expires_at < ?",
                        (time.time(),),
                    )
                    conn.commit()

            total = signals_deleted + alerts_deleted
            if total > 0:
                logger.info(
                    f"Cleanup removed {signals_deleted} signals and {alerts_deleted} alerts"
                )
            return total
        except Exception as e:
            logger.error(f"Cleanup failed: {e}")
            return 0


# Global database instance
_db: Optional[Database] = None


def get_database(db_path: str = "nids.db", retention_days: int = 14) -> Database:
    """Get or create global database instance"""
    global _db
    if _db is None:
        _db = Database(db_path, retention_days)
    return _db
