"""
nids/api/alerts.py
REST API endpoints for alert queries
"""

import logging
from typing import Optional, List
from datetime import datetime, timedelta

from fastapi import APIRouter, HTTPException, Query, Request
from pydantic import BaseModel


logger = logging.getLogger("nids.api.alerts")


router = APIRouter()


class AlertResponse(BaseModel):
    """Alert response model"""

    id: str
    timestamp: float
    timestamp_human: str
    severity: str
    title: str
    description: str
    src_ip: str
    dst_ip: str
    dst_port: Optional[int]
    proto: str
    rule_ids: List[str]
    signal_count: int
    score: int


class AlertListResponse(BaseModel):
    """Paginated alert list response"""

    alerts: List[AlertResponse]
    total: int
    limit: int
    offset: int


class StatsResponse(BaseModel):
    """Statistics response"""

    total_alerts: int
    by_severity: dict
    top_ips: List[dict]
    rule_hits: List[dict]


class MetricsResponse(BaseModel):
    """Traffic metrics response"""

    packets_per_sec: float
    total_packets: int
    packets_dropped: int
    queue_depth: int


@router.get("/alerts", response_model=AlertListResponse)
async def get_alerts(
    request: Request,
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    severity: Optional[str] = None,
    src_ip: Optional[str] = None,
    rule_id: Optional[str] = None,
    since: Optional[float] = None,
):
    """Get paginated alerts with optional filters"""
    db: request.app.state.database.__class__ = request.app.state.database

    # Get alerts
    alerts = db.get_alerts(
        limit=limit,
        offset=offset,
        severity=severity,
        src_ip=src_ip,
        rule_id=rule_id,
        since=since,
    )

    # Convert to response format
    alert_responses = []
    for alert in alerts:
        alert_responses.append(
            AlertResponse(
                id=alert["id"],
                timestamp=alert["timestamp"],
                timestamp_human=datetime.fromtimestamp(alert["timestamp"]).strftime(
                    "%Y-%m-%d %H:%M:%S"
                ),
                severity=alert["severity"],
                title=alert["title"],
                description=alert["description"],
                src_ip=alert["src_ip"],
                dst_ip=alert["dst_ip"],
                dst_port=alert["dst_port"],
                proto=alert["proto"],
                rule_ids=alert["rule_ids"].split(",") if alert["rule_ids"] else [],
                signal_count=alert["signal_count"],
                score=alert["score"],
            )
        )

    return AlertListResponse(
        alerts=alert_responses,
        total=len(alert_responses),
        limit=limit,
        offset=offset,
    )


@router.get("/alerts/{alert_id}", response_model=AlertResponse)
async def get_alert(alert_id: str, request: Request):
    """Get a single alert by ID"""
    db: request.app.state.database.__class__ = request.app.state.database

    alerts = db.get_alerts(limit=1, offset=0)
    alert = next((a for a in alerts if a["id"] == alert_id), None)

    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")

    return AlertResponse(
        id=alert["id"],
        timestamp=alert["timestamp"],
        timestamp_human=datetime.fromtimestamp(alert["timestamp"]).strftime(
            "%Y-%m-%d %H:%M:%S"
        ),
        severity=alert["severity"],
        title=alert["title"],
        description=alert["description"],
        src_ip=alert["src_ip"],
        dst_ip=alert["dst_ip"],
        dst_port=alert["dst_port"],
        proto=alert["proto"],
        rule_ids=alert["rule_ids"].split(",") if alert["rule_ids"] else [],
        signal_count=alert["signal_count"],
        score=alert["score"],
    )


@router.get("/stats", response_model=StatsResponse)
async def get_stats(request: Request):
    """Get alert statistics"""
    db: request.app.state.database.__class__ = request.app.state.database

    # Get severity counts
    by_severity = db.get_alert_counts_by_severity()

    # Get top IPs
    top_ips = db.get_top_attacking_ips(limit=10)

    # Get rule hit counts
    rule_hits = db.get_rule_hit_counts(limit=10)

    # Total alerts
    total_alerts = sum(by_severity.values())

    return StatsResponse(
        total_alerts=total_alerts,
        by_severity=by_severity,
        top_ips=top_ips,
        rule_hits=rule_hits,
    )


@router.get("/metrics", response_model=MetricsResponse)
async def get_metrics(request: Request):
    """Get real-time traffic metrics"""
    from nids.pipeline import get_pipeline

    pipeline = get_pipeline()
    if pipeline is None:
        return MetricsResponse(
            packets_per_sec=0.0,
            total_packets=0,
            packets_dropped=0,
            queue_depth=0,
        )

    metrics = pipeline.get_metrics()

    return MetricsResponse(
        packets_per_sec=round(metrics.packets_per_sec, 1),
        total_packets=metrics.packets_processed,
        packets_dropped=metrics.packets_dropped,
        queue_depth=metrics.queue_depth,
    )
