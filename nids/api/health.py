"""
nids/api/health.py
Health and readiness check endpoints
"""

import logging
from datetime import datetime

from fastapi import APIRouter, Request


logger = logging.getLogger("nids.api.health")


router = APIRouter()


@router.get("/health")
async def health_check(request: Request):
    """Basic health check"""
    return {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat(),
    }


@router.get("/ready")
async def readiness_check(request: Request):
    """Readiness check with dependency status"""
    checks = {}

    # Check database
    try:
        db = request.app.state.database
        # Simple query to verify connection
        db.get_alerts(limit=1)
        checks["database"] = "ok"
    except Exception as e:
        checks["database"] = f"error: {str(e)}"

    # Check WebSocket manager
    try:
        ws_manager = request.app.state.ws_manager
        checks["websocket"] = f"connected: {len(ws_manager.active_connections)}"
    except Exception as e:
        checks["websocket"] = f"error: {str(e)}"

    # Overall status
    all_ok = all(v == "ok" or v.startswith("connected") for v in checks.values())

    return {
        "status": "ready" if all_ok else "not_ready",
        "checks": checks,
        "timestamp": datetime.utcnow().isoformat(),
    }
